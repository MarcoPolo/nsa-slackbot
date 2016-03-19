extern crate slack;
extern crate rustc_serialize;
extern crate sodiumoxide;

use std::env;
use std::process;
use std::collections::HashMap;
use rustc_serialize::json;
use rustc_serialize::base64;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::io::{Error, ErrorKind};
use std::path::Path;

use rustc_serialize::base64::ToBase64;
use rustc_serialize::base64::FromBase64;

use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::pwhash;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::PUBLICKEYBYTES;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::SECRETKEYBYTES;

use std::io::BufRead;

// Nonce is null because we use a random ephemeral public key for every write.
const NULL_NONCE: box_::Nonce = box_::Nonce([0; box_::NONCEBYTES]);

const B64_CONFIG: base64::Config = base64::Config{
    char_set: base64::UrlSafe,
    newline: base64::Newline::LF,
    pad: true,
    line_length: None
};

// TODO parse slack's <> things
//

#[derive(Debug)]
pub struct WrappedData {
    ephemeral_pub_key: [u8; PUBLICKEYBYTES],
    data: Vec<u8>,
}

impl base64::ToBase64 for WrappedData {
    fn to_base64(&self, config: base64::Config) -> String {
        let pk = self.ephemeral_pub_key.to_base64(config);
        let data = self.data.to_base64(config);
        pk + &" " + &data
    }
}

fn to_wrapped_data(line: &str) -> Result<WrappedData, base64::FromBase64Error> {
    let mut words = line.split_whitespace();

    if let (Some(pk_str), Some(data_str)) = (words.next(), words.next()) {
        let pk = try!(pk_str.from_base64());
        let data = try!(data_str.from_base64());
        let mut sized_pk: [u8; PUBLICKEYBYTES] = [0; PUBLICKEYBYTES];
        for (a, b) in sized_pk.iter_mut().zip(pk.into_iter()) {
            *a = b;
        }

        return Ok(WrappedData{ephemeral_pub_key: sized_pk, data: data});
    }

    Err(base64::FromBase64Error::InvalidBase64Length)
}

#[derive(RustcDecodable, RustcEncodable)]
pub struct SimpleLog {
    username: String,
    channel: String,
    text: String,
}

struct MyHandler {
    user_map: HashMap<String, slack::User>,
    log_file: String,
    raw_log_file: String,
    their_pk: box_::PublicKey,
}

fn find_user (cli: &slack::RtmClient, uid: String) -> Option<slack::User> {
    cli.get_users().into_iter().find(|u| u.id == uid)
}

fn find_channel (cli: &slack::RtmClient, cid: String) -> Option<slack::Channel> {
    cli.get_channels().into_iter().find(|c| c.id == cid)
}

fn append_chat_log (key: &box_::PublicKey, log: &SimpleLog, location: &String) -> Result<(), io::Error> {
    if let Ok(json_log) = json::encode(log) {
        append_str_log(key, json_log.as_str(), location)
    } else {
        Err(Error::new(ErrorKind::Other, "failed to encode json"))
    }
}

fn wrap_with_crypto (their_pk: &box_::PublicKey, plaintext: &[u8]) -> Result<(Vec<u8>, [u8; PUBLICKEYBYTES]), io::Error> {
    let (ephemeral_pk, ephemeral_sk) = box_::gen_keypair();
    let ciphertext = box_::seal(plaintext, &NULL_NONCE, their_pk, &ephemeral_sk);
    let box_::PublicKey(ephemeral_pk_bytes) = ephemeral_pk;

    Ok((ciphertext, ephemeral_pk_bytes))
}

fn append_str_log (key: &box_::PublicKey, s: &str, location: &String) -> Result<(), io::Error> {
    let mut file = try!(OpenOptions::new().write(true).append(true).open(Path::new(location)));
    let (ciphertext, nonce) = try!(wrap_with_crypto(key, s.as_bytes()));
    let d = WrappedData{ephemeral_pub_key: nonce, data: ciphertext};
    try!(file.write_all(d.to_base64(B64_CONFIG).as_bytes()));
    try!(writeln!(file, ""));
    Ok(())
}

fn open_str (k: &box_::SecretKey, line: &str) -> Option<String> {
    if let Ok(wrapped_data) = to_wrapped_data(line) {
        let ephemeral_pub_key = box_::PublicKey(wrapped_data.ephemeral_pub_key);
        if let Ok(pt) = box_::open(&wrapped_data.data[..], &NULL_NONCE, &ephemeral_pub_key, k) {
            if let Ok(s) = String::from_utf8(pt) {
                return Some(s);
            }
        }
    }
    None
}


#[allow(unused_variables)]
impl slack::EventHandler for MyHandler {
    fn on_event(&mut self, cli: &mut slack::RtmClient, event: Result<&slack::Event, slack::Error>, raw_json: &str) {
        match event {
            Ok(evt) => {
                match *evt {
                    slack::Event::Message(ref message) => {
                        match message.clone() {
                            slack::Message::Standard { text: Some(text), user: Some(user), channel: Some(channel), ..} => {
                                if let (Some(u), Some(c)) = (find_user(&cli, user), find_channel(&cli, channel)){
                                    match append_chat_log(&self.their_pk, &SimpleLog{username: u.name, channel: c.name, text: text}, &self.log_file) {
                                        Ok(_) => {},
                                        Err(e) => println!("Failed to write chat log: {:?}", e)
                                    }

                                    match append_str_log(&self.their_pk, raw_json, &self.raw_log_file) {
                                        Ok(_) => {},
                                        Err(e) => println!("Failed to write raw log: {:?}", e)
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            },
            Err(_) => {},
        }
    }

    fn on_ping(&mut self, cli: &mut slack::RtmClient) {
        println!("on_ping");
    }

    fn on_close(&mut self, cli: &mut slack::RtmClient) {
        println!("on_close");
    }

    fn on_connect(&mut self, cli: &mut slack::RtmClient) {
        println!("on_connect");
        self.save_users(cli);
    }
}

impl MyHandler {
    fn save_users(&mut self, cli: &slack::RtmClient) {
        for u in cli.get_users().into_iter() {
            let id = u.id.clone();
            self.user_map.insert(id, u);
        }
    }
}

fn run_handler (handler: &mut MyHandler, slack_token: &String) {
    let mut cli = slack::RtmClient::new(slack_token);
    let r = cli.login_and_run::<_>(handler);

    match r {
        Ok(_) => {}
        Err(err) => panic!("Error: {}", err),
    }
}

fn read_from_env(env: &str) -> Vec<u8> {
    match env::var(env).map(|s| { s.from_base64().unwrap() }) {
        Ok(val) => val,
        Err(_) => {
            panic!("No {:?} set", env);
        }
    }
}

fn read_pub_key_from_env(env: &str) -> Option<box_::PublicKey> {
    let pk_bytes: Vec<u8> = read_from_env(env);

    let mut sized_pk: [u8; PUBLICKEYBYTES] = [0; PUBLICKEYBYTES];
    for (a, b) in sized_pk.iter_mut().zip(pk_bytes.into_iter()) {
        *a = b;
    }
    return Some(box_::PublicKey(sized_pk));
}

fn read_secret_key_from_env(env: &str) -> Option<box_::SecretKey> {
    let sk_bytes: Vec<u8> = read_from_env(env);

    let mut sized_pk: [u8; SECRETKEYBYTES] = [0; SECRETKEYBYTES];
    for (a, b) in sized_pk.iter_mut().zip(sk_bytes.into_iter()) {
        *a = b;
    }
    return Some(box_::SecretKey(sized_pk));
}

fn main() {

    if let Ok(_) = env::var("GEN_KEYPAIR") {
        let (pk, sk) = box_::gen_keypair();
        let box_::PublicKey(pk_bytes) = pk;
        let box_::SecretKey(sk_bytes) = sk;

        println!("Public Key: {:?}", pk_bytes.to_base64(B64_CONFIG));
        println!("Secret Key: {:?}", sk_bytes.to_base64(B64_CONFIG));

        process::exit(0);
    }

    let public_key = read_pub_key_from_env("NSA_PUBLIC_KEY").unwrap();

    if let Ok(_) = env::var("NSA_DECRYPT") {
        let secret_key = read_secret_key_from_env("NSA_SECRET_KEY").unwrap();

        let stdin = io::stdin();
        let mut stdin = stdin.lock();
        let mut buffer = String::new();
        while stdin.read_line(&mut buffer).unwrap_or(0) > 0 {
            println!("{:?}", open_str(&secret_key, buffer.as_str()).unwrap_or("None".to_string()));
            buffer.clear();
        }

        process::exit(0);
    }

    let slack_token: String;
    match env::var("NSA_SLACK_TOKEN") {
        Ok(val) => slack_token = val,
        Err(_) => panic!("No NSA_SLACK_TOKEN set"),
    }

    match (env::var("NSA_LOG_FILE"), env::var("NSA_RAW_LOG_FILE")) {
        (Ok(log_file), Ok(raw_log_file)) => {
            let mut handler = MyHandler{
                user_map: HashMap::new(),
                log_file: log_file,
                raw_log_file: raw_log_file,
                their_pk: public_key,
            };

            run_handler(&mut handler, &slack_token)
        },

        (Err(_), Ok(_)) => panic!("No NSA_LOG_FILE set"),
        (Ok(_), Err(_)) => panic!("No NSA_RAW_LOG_FILE set"),
        (Err(_), Err(_)) => panic!("No NSA_RAW_LOG_FILE or NSA_LOG_FILE set"),

    }


}
