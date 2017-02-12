#![crate_name = "cerith"]
#![crate_type = "lib"]

extern crate regex;
extern crate time;

use regex::Regex;
use std::collections::HashSet;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

// General config stuff
const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");
static VERSION_NONE: &'static str = "unknown";
static NAME: &'static str = "Cerith";
static ADMINS: &'static [&'static str] = &["wink!fhtagn@cordelia.art-core.org"];
static DEBUG: bool = true;

// IRC config stuff
pub const DEFAULT_NICKNAME: &'static str = "Cerith";
pub const DEFAULT_REALNAME: &'static str = "Cerith";
pub const DEFAULT_USERNAME: &'static str = "Cerith";
static USERMODE: i32 = 8;
static CTCP_DELIM: &'static str = "\x01";

// Messages to be sent.
static MSG_QUIT: &'static str = "Fin.";
static MSG_GREET: &'static str = "Hello World!";
static MSG_IQUIT: &'static str = ":(";
static MSG_NOPE: &'static str = "You're not the boss of me.";

// Commands that are recognized
static CMD_PREFIX: &'static str = "!";
static CMD_QUIT: &'static str = "quit";
static CMD_JOIN: &'static str = "join";
static CMD_PART: &'static str = "part";
static CMD_SAY: &'static str = "say";
static CMD_MODE: &'static str = "mode";

fn debug(msg: String) {
    if DEBUG {
        println!("___ {}", msg);
    }
}

pub fn get_version() -> String {
    format!("{} {}", NAME, VERSION.unwrap_or(VERSION_NONE))
}

pub struct Config {
    nickname: String,
    username: String,
    realname: String,
}

pub struct IRCStream {
    //stream: IRCStreamTypes,
    stream: TcpStream,
    pub host: String,
    pub port: i32,
    pub is_authenticated: bool,
    pub config: Config,
}

struct User<'a> {
    nick: &'a str,
    ident: &'a str,
    host: &'a str,
}

enum Event {
    Command,
    CommandCancelled,
    Connected,
    CTCP,
    PingPong,
    PrivMsg,
    Quit(String),
    Unknown,
    Unprivileged,
}

fn get_utc_time(msec: bool) -> String {
    let now = time::now_utc().to_timespec();
    let ss = now.sec.to_string();
    let ns = now.nsec.to_string();
    if msec {
        ss + &ns[0..3]
    } else {
        ss
    }
}

fn get_local_time() -> String {
    let now = time::now_utc();
    //
    // This would need %Z support in strftime on Windows :(
    // let now = time::now();
    // let fmt = "%a %d %b %Y %H:%M:%S %Z";
    // let result = match now.strftime(fmt) {
    // Ok(v) => v,
    // _     => now.rfc822(),
    // };
    // return format!("{}", result).replace(",","");
    //
    format!("{}", now.rfc822()).replace(",", "")
}

fn parse_hostmask(s: &str) -> User {
    let re = Regex::new(r"^(.*)!(.*)@(.*)").unwrap();
    if re.is_match(s) {
        let x = re.captures(s).unwrap();
        let nick = x.get(1).unwrap();
        let ident = x.get(2).unwrap();
        let host = x.get(3).unwrap();

        User {
            nick: nick.as_str(),
            ident: ident.as_str(),
            host: host.as_str(),
        }
    } else {
        panic!("Cannot parse host mask: {}", s);
    }
}

fn join_hostmask(user: &User) -> String {
    format!("{}!{}@{}", user.nick, user.ident, user.host)
}

fn is_command(input: &str, command: &str) -> bool {
    let full = CMD_PREFIX.to_string() + command;
    let len = full.len();

    input == full || &input[0..len] == full
}

fn has_privilege(user: &User) -> bool {
    for admin in ADMINS {
        if &join_hostmask(user) == admin {
            return true;
        }
    }
    false
}

impl IRCStream {
    pub fn run(&mut self, nickname: String, username: String, realname: String) {
        let mut quit_msg = MSG_QUIT.to_string();
        let mut rcvd;
        let mut initialized = false;

        let mut cfg = Config {
            nickname: nickname.to_string(),
            username: username.to_string(),
            realname: realname.to_string(),
        };
        self.config = cfg;

        loop {
            rcvd = self.read_response();
            let line = &rcvd[0][..];
            debug(format!("R {:?}", line));

            if !initialized {
                self.send_nick(&nickname);
                self.send_user(&username, USERMODE, &realname);
                initialized = true;
                continue;
            }

            let event = self.handle_line(line);
            match event {
                Event::Quit(v) => {
                    debug(format!("Event::Quit {}", v));
                    quit_msg = v;
                    break;
                }
                Event::Connected => {
                    debug(format!("Event::Connected"));
                }
                _ => (),
            }
        }

        // shutting down
        thread::sleep(Duration::new(0, 200));
        self.send_quit(&quit_msg[..]);
        println!("");
    }

    pub fn connect(host: String, port: i32) -> Result<IRCStream, Error> {
        let conn_string = format!("{}:{}", host, port);
        //let mut tcp_stream = TcpStream::connect(&conn_string[..]).unwrap();
        let tcp_stream = match TcpStream::connect(&conn_string[..]) {
            Ok(x) => x,
            Err(_) => return Err(Error::new(ErrorKind::Other, "nope")),
        };
        let config = Config{
            nickname: DEFAULT_NICKNAME.to_string(),
            realname: DEFAULT_REALNAME.to_string(),
            username: DEFAULT_USERNAME.to_string(),
        };
        let socket = IRCStream {
            stream: tcp_stream,
            host: host,
            port: port,
            is_authenticated: false,
            config: config,
        };
        Ok(socket)
    }

    pub fn read_response(&mut self) -> Vec<String> {
        // Carriage return
        let cr = 0x0d;
        // Line Feed
        let lf = 0x0a;
        let mut line_buffer: Vec<u8> = Vec::new();
        let mut all: Vec<String> = Vec::new();
        while line_buffer.len() < 2 ||
              (line_buffer[line_buffer.len() - 1] != lf &&
               line_buffer[line_buffer.len() - 2] != cr) {
            let byte_buffer: &mut [u8] = &mut [0];
            match self.stream.read(byte_buffer) {
                Ok(_) => {}
                Err(_) => println!("Error Reading!"),
            }
            line_buffer.push(byte_buffer[0]);
        }

        match String::from_utf8(line_buffer.clone()) {
            Ok(res) => {
                // println!("DEBUG {:?}", res);
                all.push(res);
                // line_buffer = Vec::new();
            }
            Err(_) => panic!("Failed to read the response"),
        }

        all
    }

    fn send_raw(&mut self, msg: &str) -> Result<(), Error> {
        let sent = self.stream.write_fmt(format_args!("{}", msg));
        debug(format!("S {:?} {:?}", msg, sent));

        sent
    }

    fn send_ctcp(&mut self, to: &str, command: &str, msg: &str) {
        let delim = CTCP_DELIM.to_string();
        let ctcp = delim + command + " " + msg + CTCP_DELIM;
        self.send_privmsg(to, &ctcp[..]);
    }

    fn send_ctcp_reply(&mut self, to: &str, command: &str, msg: &str) {
        let delim = CTCP_DELIM.to_string();
        let ctcp = delim + command + " " + msg + CTCP_DELIM;
        self.send_notice(to, &ctcp[..]);
    }

    fn send_join(&mut self, channel: &str) {
        self.send_raw(&(format!("JOIN {}\n", channel)));
    }

    fn send_mode(&mut self, channel: &str, msg: &str) {
        self.send_raw(&(format!("MODE {} {}\n", channel, msg)));
    }

    fn send_nick(&mut self, msg: &str) {
        self.send_raw(&(format!("NICK :{}\n", msg)));
    }

    fn send_notice(&mut self, to: &str, msg: &str) {
        self.send_raw(&(format!("NOTICE {} :{}\n", to, msg)));
    }

    fn send_part(&mut self, channel: &str, msg: &str) {
        if msg.is_empty() {
            let _ = self.send_raw(&(format!("PART {}\n", channel)));
        } else {
            let _ = self.send_raw(&(format!("PART {} :{}\n", channel, msg)));
        }
    }

    fn send_pong(&mut self, msg: &str) {
        self.send_raw(&(format!("PONG :{}\n", msg)));
    }

    fn send_privmsg(&mut self, to: &str, msg: &str) {
        self.send_raw(&(format!("PRIVMSG {} :{}\n", to, msg)));
    }

    fn send_user(&mut self, name: &str, mode: i32, realname: &str) {
        self.send_raw(&(format!("USER {} {} * :{}\n", name, mode, realname)));
    }

    fn send_quit(&mut self, msg: &str) {
        self.send_raw(&(format!("QUIT :{}\n", msg)));
    }

    fn handle_line(&mut self, line: &str) -> Event {
        let event_priv = format!(":(.*) PRIVMSG {} :(.*)\r\n", self.config.nickname);
        let event_ping = "^PING\\s+:(.*)";
        let event_motd = ".*End of MOTD command.*";

        let re_motd = Regex::new(&event_motd[..]).unwrap();
        let re_ping = Regex::new(&event_ping[..]).unwrap();
        let re_priv = Regex::new(&event_priv[..]).unwrap();

        let event_cmd_join = format!("{}{}\\s+(.*)", CMD_PREFIX, CMD_JOIN);
        let event_cmd_part = format!("{}{}\\s+(\\S+)(\\s+)?(.*)?", CMD_PREFIX, CMD_PART);
        let event_cmd_quit = format!("{}{}(\\s+)?(.*)?", CMD_PREFIX, CMD_QUIT);
        let event_cmd_say = format!("{}{}\\s+(\\S+)\\s+(.+)", CMD_PREFIX, CMD_SAY);
        let event_cmd_mode = format!("{}{}\\s+(\\S+)\\s+(.+)", CMD_PREFIX, CMD_MODE);

        let re_cmd_join = Regex::new(&event_cmd_join[..]).unwrap();
        let re_cmd_part = Regex::new(&event_cmd_part[..]).unwrap();
        let re_cmd_quit = Regex::new(&event_cmd_quit[..]).unwrap();
        let re_cmd_say = Regex::new(&event_cmd_say[..]).unwrap();
        let re_cmd_mode = Regex::new(&event_cmd_mode[..]).unwrap();

        if re_motd.is_match(line) {
            debug(format!("CONNECTED"));
            thread::sleep(Duration::new(1, 0));

            for admin in ADMINS {
                self.send_privmsg(admin, MSG_GREET);
            }

            return Event::Connected;
        } else if re_ping.is_match(line) {
            let payload = re_ping.captures(line).unwrap().get(1).unwrap().as_str();
            debug(format!("PONG {}", payload));
            self.send_pong(payload);

            return Event::PingPong;
        } else if re_priv.is_match(line) {
            let caps = re_priv.captures(line).unwrap();
            let sender = caps.get(1).unwrap().as_str();
            let msg = caps.get(2).map_or("", |m| m.as_str());
            let user = parse_hostmask(sender);

            if msg.len() < 1 {
                debug(format!("PRIVMSG TOO SHORT {}", sender));
                return Event::PrivMsg;
            }

            // these are the bot commands with prefix
            if msg.chars().nth(0) == CMD_PREFIX.chars().nth(0) {
                if !has_privilege(&user) {
                    self.send_privmsg(user.nick, MSG_NOPE);

                    return Event::Unprivileged;
                }
                if is_command(msg, CMD_QUIT) {
                    let caps_cmd = re_cmd_quit.captures(msg).unwrap();
                    let quit_msg = caps_cmd.get(2).map_or("", |m| m.as_str());
                    debug(format!("EXITING {}", quit_msg));
                    self.send_privmsg(user.nick, MSG_IQUIT);

                    return Event::Quit(quit_msg.to_string());
                } else if is_command(msg, CMD_JOIN) {
                    let caps_cmd = re_cmd_join.captures(msg).unwrap();
                    let channel = caps_cmd.get(1).map_or("", |m| m.as_str());
                    debug(format!("JOIN {}|{}|{}", sender, msg, channel));
                    if !channel.is_empty() {
                        self.send_join(channel);
                    }
                } else if is_command(msg, CMD_PART) {
                    let caps_cmd = re_cmd_part.captures(msg).unwrap();
                    let channel = caps_cmd.get(1).map_or("", |m| m.as_str());
                    let part_msg = caps_cmd.get(3).map_or("", |m| m.as_str());
                    debug(format!("PART {}|{}|{}|{}", sender, msg, channel, part_msg));
                    self.send_part(channel, part_msg);
                } else if is_command(msg, CMD_MODE) {
                    let caps_cmd = re_cmd_mode.captures(msg).unwrap();
                    let channel = caps_cmd.get(1).unwrap().as_str();
                    let rest = caps_cmd.get(2).map_or("", |m| m.as_str());

                    if rest.len() < 2 {
                        let lists: HashSet<_> = ["I" /* invitations masks */,
                                                 "e" /* exemptions masks */]
                            .iter()
                            .cloned()
                            .collect();

                        if rest.len() == 1 && lists.contains(rest) {
                            debug(format!("CHANMODE L {}|{}|{}|{}", sender, msg, channel, rest));
                            self.send_mode(channel, rest);

                            return Event::Command;
                        }
                        return Event::CommandCancelled;
                    }

                    let first = &rest[0..1];
                    let second = &rest[1..2];

                    let pm: HashSet<_> = ["+", "-"].iter().cloned().collect();
                    if !pm.contains(first) {
                        return Event::CommandCancelled;
                    }

                    // https://www.alien.net.au/irc/chanmodes.html
                    let arity_0: HashSet<_> =
                        ["c" /* no colors */, "C" /* no ctcp */,
                         "m" /* moderated */, "n" /* no external messages */,
                         "r" /* registered users only */,
                         "R" /* registered users only */, "s" /* secret */,
                         "S" /* strip colors */, "t" /* topic lock */,
                         "z" /* secure joins only */]
                            .iter()
                            .cloned()
                            .collect();

                    let arity_1: HashSet<_> = ["b" /* ban */, "h" /* half-op */,
                                               "k" /* channel key */,
                                               "l" /* channel limit */,
                                               "o" /* operator */, "v" /* voice */]
                        .iter()
                        .cloned()
                        .collect();

                    if arity_0.contains(second) {
                        let mode = &rest[0..2];
                        debug(format!("CHANMODE 0 {}|{}|{}|{}", sender, msg, channel, mode));
                        self.send_mode(channel, mode);
                    } else if arity_1.contains(second) {
                        let mode = &rest[0..2];
                        if rest.len() < 4 {
                            return Event::CommandCancelled;
                        }
                        let arg = &rest[3..].trim();
                        debug(format!("CHANMODE 1 {}|{}|{}|{}|{}",
                                      sender,
                                      msg,
                                      channel,
                                      mode,
                                      arg));
                        self.send_mode(channel, &rest[..]);
                    } else {
                        debug(format!("CHANMODE ? {}|{}|{}", sender, msg, channel));
                        // send_privmsg(stream, channel, &say_msg2[..]);
                        return Event::CommandCancelled;
                    }
                } else if is_command(msg, CMD_SAY) {
                    let caps_cmd = re_cmd_say.captures(msg).unwrap();
                    let channel = caps_cmd.get(1).map_or("", |m| m.as_str());
                    if channel.is_empty() {
                        return Event::CommandCancelled;
                    }
                    let say_msg = caps_cmd.get(2).map_or("", |m| m.as_str());
                    if say_msg.is_empty() {
                        return Event::CommandCancelled;
                    } else {
                        if say_msg.len() > 4 && &say_msg[0..4] == "/me " {
                            let ctcp = "ACTION";
                            debug(format!("ACT {}|{}|{}|{}", sender, msg, channel, &say_msg[4..]));
                            self.send_ctcp(channel, ctcp, &say_msg[4..])
                        } else {
                            debug(format!("SAY {}|{}|{}|{}", sender, msg, channel, say_msg));
                            self.send_privmsg(channel, say_msg);
                        }
                    }
                } else {
                    debug(format!("CMD {}|{}", sender, msg));
                }

                return Event::Command;
            } else if &msg[0..1] == "\x01" {
                // CTCP stuff
                let len = msg.len();
                if len < 3 || &msg[len - 1..len] != "\x01" {
                    debug(format!("PRIVMSG CTCP:FAIL {}|{}", sender, msg));
                    return Event::PrivMsg;
                }
                let payload = &msg[1..len - 1];
                debug(format!("PRIVMSG CTCP:OK {}|{}", sender, payload));

                if payload == "VERSION" {
                    let command = "VERSION";
                    let reply = get_version();
                    debug(format!("PRIVMSG CTCP:{} {}|{}", command, sender, reply));
                    self.send_ctcp_reply(sender, command, &reply[..]);

                    return Event::CTCP;
                } else if payload == "TIME" {
                    let command = "TIME";
                    let reply = get_local_time();
                    debug(format!("PRIVMSG CTCP:{} {}|{}", command, sender, reply));
                    self.send_ctcp_reply(sender, command, &reply[..]);

                    return Event::CTCP;
                } else if &payload[0..4] == "PING" {
                    if payload.len() < 6 {
                        return Event::Unknown;
                    }
                    // let rest = &payload[5..];
                    let command = "PING";

                    let reply = get_utc_time(true);
                    debug(format!("PRIVMSG CTCP:{} {}|{}", command, sender, reply));
                    self.send_ctcp_reply(sender, command, &reply[..]);
                }
            } else {
                debug(format!("PRIVMSG {}|{}", sender, msg));

                return Event::PrivMsg;
            }
        }
        return Event::Unknown;
    }
}
