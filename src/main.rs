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

use std::io::BufRead;

const APP_SALT: [u8; 32] = [10, 114, 205, 187, 185, 221, 149, 162, 162, 65, 134, 167, 216, 87, 26, 195, 184, 203, 106, 155, 0, 243, 142, 180, 223, 88, 83, 179, 230, 4, 217, 25];

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
    ephemeral_pub_key: [u8; 24],
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
        let mut sized_pk: [u8; 24] = [0; 24];
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
    key: secretbox::Key,
}

fn find_user (cli: &slack::RtmClient, uid: String) -> Option<slack::User> {
    cli.get_users().into_iter().find(|u| u.id == uid)
}

fn find_channel (cli: &slack::RtmClient, cid: String) -> Option<slack::Channel> {
    cli.get_channels().into_iter().find(|c| c.id == cid)
}

fn append_chat_log (key: &secretbox::Key, log: &SimpleLog, location: &String) -> Result<(), io::Error> {
    if let Ok(json_log) = json::encode(log) {
        append_str_log(key, json_log.as_str(), location)
    } else {
        Err(Error::new(ErrorKind::Other, "failed to encode json"))
    }
}

fn wrap_with_crypto (key: &secretbox::Key, plaintext: &str) -> Result<(Vec<u8>, [u8; 24]), io::Error> {
    let nonce = secretbox::gen_nonce();
    let ciphertext = secretbox::seal(plaintext.as_bytes(), &nonce, key);

    let secretbox::xsalsa20poly1305::Nonce(nonce_bytes) = nonce;
    Ok((ciphertext, nonce_bytes))
}

fn append_str_log (key: &secretbox::Key, s: &str, location: &String) -> Result<(), io::Error> {
    let mut file = try!(OpenOptions::new().write(true).append(true).open(Path::new(location)));
    let (ciphertext, nonce) = try!(wrap_with_crypto(key, s));
    let d = WrappedData{ephemeral_pub_key: nonce, data: ciphertext};
    try!(file.write_all(d.to_base64(B64_CONFIG).as_bytes()));
    try!(writeln!(file, ""));
    Ok(())
}

fn open_str (key: &secretbox::Key, line: &str) -> Option<String> {
    if let Ok(wrapped_data) = to_wrapped_data(line) {
        let nonce = secretbox::xsalsa20poly1305::Nonce(wrapped_data.ephemeral_pub_key);
        if let Ok(pt) = secretbox::open(&wrapped_data.data[..], &nonce, key) {
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
                                    match append_chat_log(&self.key, &SimpleLog{username: u.name, channel: c.name, text: text}, &self.log_file) {
                                        Ok(_) => {},
                                        Err(e) => println!("Failed to write chat log: {:?}", e)
                                    }

                                    match append_str_log(&self.key, raw_json, &self.raw_log_file) {
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

fn main() {

    if let Ok(_) = env::var("GEN_KEYPAIR") {
        let (pk, sk) = box_::gen_keypair();
        let box_::curve25519xsalsa20poly1305::PublicKey(pk_bytes) = pk;
        let box_::curve25519xsalsa20poly1305::SecretKey(sk_bytes) = sk;

        println!("Public Key: {:?}", pk_bytes.to_base64(B64_CONFIG));
        println!("Secret Key: {:?}", sk_bytes.to_base64(B64_CONFIG));
        process::exit(0);
    }

    let crypto_key: String;
    match env::var("NSA_CRYPTO_KEY") {
        Ok(val) => crypto_key = val,
        Err(_) => panic!("No NSA_CRYPTO_KEY set"),
    }

    let mut derived_key = secretbox::Key([0; secretbox::KEYBYTES]);
    {
        let secretbox::Key(ref mut kb) = derived_key;
        pwhash::derive_key(kb, crypto_key.as_bytes(), &pwhash::scryptsalsa208sha256::Salt(APP_SALT),
                           pwhash::OPSLIMIT_INTERACTIVE,
                           pwhash::MEMLIMIT_INTERACTIVE).unwrap();
    }


    if let Ok(_) = env::var("NSA_DECRYPT") {

        let stdin = io::stdin();
        let mut stdin = stdin.lock();
        let mut buffer = String::new();
        while stdin.read_line(&mut buffer).unwrap_or(0) > 0 {
            println!("{:?}", open_str(&derived_key, buffer.as_str()).unwrap_or("None".to_string()));
            buffer.clear();
        }

        process::exit(0);
    }

    let slack_token: String;
    match env::var("NSA_SLACK_TOKEN") {
        Ok(val) => slack_token = val,
        Err(_) => panic!("No NSA_SLACK_TOKEN set"),
    }


    let (ourpk, oursk) = box_::gen_keypair();
    let (theirpk, theirsk) = box_::gen_keypair();
    let our_precomputed_key = box_::precompute(&theirpk, &oursk);
    let nonce = box_::gen_nonce();
    let plaintext = b"plaintext";
    let ciphertext = box_::seal_precomputed(plaintext, &nonce, &our_precomputed_key);
    // this will be identical to our_precomputed_key
    let their_precomputed_key = box_::precompute(&ourpk, &theirsk);
    let their_plaintext = box_::open_precomputed(&ciphertext, &nonce,
                                                 &their_precomputed_key).unwrap();


    //append_str_log(&derived_key, &"123 foobar", &"/tmp/asdf".to_string());
    //append_str_log(&derived_key, &"foobar 123", &"/tmp/asdf".to_string());
    //process::exit(0);

    match (env::var("NSA_LOG_FILE"), env::var("NSA_RAW_LOG_FILE")) {
        (Ok(log_file), Ok(raw_log_file)) => {
            let mut handler = MyHandler{
                user_map: HashMap::new(),
                log_file: log_file,
                raw_log_file: raw_log_file,
                key: derived_key
            };

            run_handler(&mut handler, &slack_token)
        },

        (Err(_), Ok(_)) => panic!("No NSA_LOG_FILE set"),
        (Ok(_), Err(_)) => panic!("No NSA_RAW_LOG_FILE set"),
        (Err(_), Err(_)) => panic!("No NSA_RAW_LOG_FILE or NSA_LOG_FILE set"),

    }


}
