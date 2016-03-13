extern crate slack;
extern crate rustc_serialize;
extern crate sodiumoxide;

use std::env;
use std::collections::HashMap;
use rustc_serialize::json;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::io::{Error, ErrorKind};
use std::path::Path;

use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::pwhash;

const APP_SALT: [u8; 32] = [10, 114, 205, 187, 185, 221, 149, 162, 162, 65, 134, 167, 216, 87, 26, 195, 184, 203, 106, 155, 0, 243, 142, 180, 223, 88, 83, 179, 230, 4, 217, 25];

// TODO parse slack's <> things

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
    let secretbox::xsalsa20poly1305::Nonce(nonce_bytes) = secretbox::gen_nonce();
    let ciphertext = secretbox::seal(plaintext.as_bytes(), &nonce, key);
    Ok((ciphertext, nonce_bytes))
}

fn append_str_log (key: &secretbox::Key, s: &str, location: &String) -> Result<(), io::Error> {
    println!("should write: {:?}", s);
    let mut file = try!(OpenOptions::new().write(true).append(true).open(Path::new(location)));
    let (ciphertext, nonce) = try!(wrap_with_crypto(key, s));
    try!(file.write_all(&nonce));
    try!(file.write_all(&ciphertext[..]));
    // try!(file.write_all(s.as_bytes()));
    try!(writeln!(file, ""));
    println!("Wrote file");
    Ok(())
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
    let slack_token: String;
    match env::var("NSA_SLACK_TOKEN") {
        Ok(val) => slack_token = val,
        Err(_) => panic!("No NSA_SLACK_TOKEN set"),
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
