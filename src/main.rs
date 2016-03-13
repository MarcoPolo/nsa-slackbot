extern crate slack;
use std::env;
use std::collections::HashMap;

struct MyHandler {
    user_map: HashMap<String, slack::User>,
}

fn find_user (cli: &slack::RtmClient, uid: String) -> Option<slack::User> {
    cli.get_users().into_iter().find(|u| u.id == uid)
}

fn find_channel (cli: &slack::RtmClient, cid: String) -> Option<slack::Channel> {
    cli.get_channels().into_iter().find(|c| c.id == cid)
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
                                    println!("User: {:?}", u.name);
                                    println!("Channel: {:?}", c.name);
                                    println!("Message: {:?}", text);
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

fn main() {
    let slack_token: String;
    match env::var("NSA_SLACK_TOKEN") {
        Ok(val) => slack_token = val,
        Err(_) => panic!("No NSA_SLACK_TOKEN set"),
    }

    let mut handler = MyHandler{
        user_map: HashMap::new(),
    };
    let mut cli = slack::RtmClient::new(&slack_token);
    let r = cli.login_and_run::<MyHandler>(&mut handler);

    match r {
        Ok(_) => {}
        Err(err) => panic!("Error: {}", err),
    }

    println!("{}", cli.get_name().unwrap());
    println!("{}", cli.get_team().unwrap().name);
}
