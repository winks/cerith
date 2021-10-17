#![crate_name = "cerith"]
#![crate_type = "lib"]

extern crate rand;
extern crate regex;
extern crate time;

use rand::Rng;
use regex::Regex;
use std::collections::HashSet;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

// General config stuff
const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");
static VERSION_NONE: &'static str = "unknown";
static NAME: &'static str = "Cerith";
static DEBUG: bool = true;
pub const DEFAULT_PORT: i32 = 6667;

// IRC config stuff
pub const DEFAULT_NICKNAME: &'static str = "Cerith";
pub const DEFAULT_REALNAME: &'static str = "Cerith";
pub const DEFAULT_USERNAME: &'static str = "Cerith";
pub const DEFAULT_USERMODE: i32 = 8; // 8 = +i, 12 = +iw
pub const DEFAULT_PREFIX: &'static str = "!";
static CTCP_DELIM: &'static str = "\x01";

// Messages to be sent.
static MSG_QUIT: &'static str = "Fin.";
static MSG_GREET: &'static str = "Hello World!";
static MSG_IQUIT: &'static str = ":(";
static MSG_NOPE: &'static str = "You're not the boss of me.";

// Commands that are recognized
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

#[derive(Debug)]
pub struct Server {
    host: String,
    port: i32,
}

#[derive(Clone, Debug)]
pub struct Reaction {
    trigger: String,
    action: String,
    occur: i32,
    log: String,
}

#[derive(Clone, Debug)]
pub struct Config {
    nickname: String,
    username: String,
    realname: String,
    usermode: i32,
    prefix: String,
    admins: Vec<String>,
    altnicks: Vec<String>,
    reactions: Vec<Reaction>,
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
    NickTaken(String),
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
    if msec { ss + &ns[0..3] } else { ss }
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

fn has_privilege(user: &User, admins: &[String]) -> bool {
    for admin in admins {
        if &join_hostmask(user) == admin {
            return true;
        }
    }
    false
}

impl Server {
    pub fn new(host: String, port: i32) -> Server {
        Server {
            host: host,
            port: port,
        }
    }
}

impl Reaction {
    pub fn new(trigger: String, action: String, occur: i32, log: String) -> Reaction {
        Reaction {
            trigger: trigger,
            action: action,
            occur: occur,
            log: log,
        }
    }
}

impl fmt::Display for Server {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

impl Config {
    pub fn new(nickname: String,
               username: String,
               realname: String,
               usermode: i32,
               prefix: String,
               admins: Vec<String>,
               altnicks: Vec<String>,
               reactions: Vec<Reaction>)
               -> Config {
        Config {
            nickname: nickname,
            username: username,
            realname: realname,
            usermode: usermode,
            prefix: prefix,
            admins: admins,
            altnicks: altnicks,
            reactions: reactions,
        }
    }
}

impl IRCStream {
    pub fn run(&mut self, config: Config) {
        let mut quit_msg = MSG_QUIT.to_string();
        let mut rcvd;
        let mut initialized = false;

        self.config = config.clone();

        let mut current_nick = config.nickname;
        let mut nick_counter = 0;
        let mut counter = 0;

        loop {
            rcvd = self.read_response();
            let line = &rcvd[0][..];
            debug(format!("R {:?}", line));

            let event = self.handle_line(line);
            match event {
                Event::NickTaken(v) => {
                    debug(format!("Event::NickTaken {}", v));
                    if nick_counter > config.altnicks.len() - 1 {
                        quit_msg = ":(".to_string();
                        break;
                    }
                    current_nick = config.altnicks.get(nick_counter).unwrap().to_string();
                    nick_counter += 1;
                }
                Event::Quit(v) => {
                    debug(format!("Event::Quit {}", v));
                    quit_msg = v;
                    break;
                }
                Event::Connected => {
                    debug("Event::Connected".to_string());
                    initialized = true;
                    continue;
                }
                _ => {
                    if counter > 0 {
                        initialized = true;
                    }
                }
            }

            if !initialized {
                self.send_nick(&current_nick);
                self.send_user(&config.username, config.usermode, &config.realname);
            }

            counter += 1
        }

        // shutting down
        thread::sleep(Duration::new(0, 200));
        self.send_quit(&quit_msg[..]);
        println!("");
    }

    pub fn connect2(host: String, port: i32) -> Result<IRCStream, Error> {
        let server = Server::new(host, port);

        IRCStream::connect(&server)
    }

    pub fn connect(server: &Server) -> Result<IRCStream, Error> {
        let conn_string = format!("{}:{}", server.host, server.port);
        //let mut tcp_stream = TcpStream::connect(&conn_string[..]).unwrap();
        let tcp_stream = match TcpStream::connect(&conn_string[..]) {
            Ok(x) => x,
            Err(_) => return Err(Error::new(ErrorKind::Other, "nope")),
        };
        let config = Config {
            nickname: DEFAULT_NICKNAME.to_string(),
            realname: DEFAULT_REALNAME.to_string(),
            username: DEFAULT_USERNAME.to_string(),
            usermode: DEFAULT_USERMODE,
            prefix: DEFAULT_PREFIX.to_string(),
            admins: Vec::new(),
            altnicks: Vec::new(),
            reactions: Vec::new(),
        };
        let socket = IRCStream {
            stream: tcp_stream,
            host: server.host.clone(),
            port: server.port,
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

    fn send_raw2(&mut self, msg: String) -> Result<(), Error> {
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
        let _ = self.send_raw(&(format!("JOIN {}\n", channel)));
    }

    fn send_mode(&mut self, channel: &str, msg: &str) {
        let _ = self.send_raw(&(format!("MODE {} {}\n", channel, msg)));
    }

    fn send_nick(&mut self, msg: &str) {
        let _ = self.send_raw2(format!("NICK :{}\n", msg));
    }

    fn send_notice(&mut self, to: &str, msg: &str) {
        let _ = self.send_raw(&(format!("NOTICE {} :{}\n", to, msg)));
    }

    fn send_part(&mut self, channel: &str, msg: &str) {
        if msg.is_empty() {
            let _ = self.send_raw(&(format!("PART {}\n", channel)));
        } else {
            let _ = self.send_raw(&(format!("PART {} :{}\n", channel, msg)));
        }
    }

    fn send_pong(&mut self, msg: &str) {
        let _ = self.send_raw(&(format!("PONG :{}\n", msg)));
    }

    fn send_privmsg(&mut self, to: &str, msg: &str) {
        let _ = self.send_raw(&(format!("PRIVMSG {} :{}\n", to, msg)));
    }

    fn send_user(&mut self, name: &str, mode: i32, realname: &str) {
        let _ = self.send_raw(&(format!("USER {} {} * :{}\n", name, mode, realname)));
    }

    fn send_quit(&mut self, msg: &str) {
        let _ = self.send_raw(&(format!("QUIT :{}\n", msg)));
    }

    fn handle_line(&mut self, line: &str) -> Event {
        let event_priv_self = format!(":(.*) PRIVMSG {} :(.*)\r\n", self.config.nickname);
        let event_priv_chan = format!(":(.*) PRIVMSG ((#|!)(\\S+)) :(.*)\r\n");
        let event_ping = "^PING\\s+:(.*)";
        let event_motd = ".*End of MOTD command.*";
        let event_nick = ":(.*) (.*) :Nickname is already in use.\r\n";

        let re_motd = Regex::new(&event_motd[..]).unwrap();
        let re_ping = Regex::new(&event_ping[..]).unwrap();
        let re_nick = Regex::new(&event_nick[..]).unwrap();
        let re_priv_self = Regex::new(&event_priv_self[..]).unwrap();
        let re_priv_chan = Regex::new(&event_priv_chan[..]).unwrap();

        let event_cmd_join = format!("{}{}\\s+(.*)", self.config.prefix, CMD_JOIN);
        let event_cmd_part = format!("{}{}\\s+(\\S+)(\\s+)?(.*)?", self.config.prefix, CMD_PART);
        let event_cmd_quit = format!("{}{}(\\s+)?(.*)?", self.config.prefix, CMD_QUIT);
        let event_cmd_say = format!("{}{}\\s+(\\S+)\\s+(.+)", self.config.prefix, CMD_SAY);
        let event_cmd_mode = format!("{}{}\\s+(\\S+)\\s+(.+)", self.config.prefix, CMD_MODE);

        let re_cmd_join = Regex::new(&event_cmd_join[..]).unwrap();
        let re_cmd_part = Regex::new(&event_cmd_part[..]).unwrap();
        let re_cmd_quit = Regex::new(&event_cmd_quit[..]).unwrap();
        let re_cmd_say = Regex::new(&event_cmd_say[..]).unwrap();
        let re_cmd_mode = Regex::new(&event_cmd_mode[..]).unwrap();

        if re_nick.is_match(line) {
            let caps = re_nick.captures(line).unwrap();
            let nick = caps.get(2).map_or("x", |m| m.as_str());
            debug(format!("Nick taken: {}", nick));

            return Event::NickTaken(nick.to_string());
        } else if re_motd.is_match(line) {
            debug("CONNECTED".to_string());
            thread::sleep(Duration::new(1, 0));

            for admin in self.config.admins.clone() {
                self.send_privmsg(&admin, MSG_GREET);
            }

            return Event::Connected;
        } else if re_ping.is_match(line) {
            let payload = re_ping.captures(line).unwrap().get(1).unwrap().as_str();
            debug(format!("PONG {}", payload));
            self.send_pong(payload);

            return Event::PingPong;
        } else if re_priv_self.is_match(line) {
            let caps   = re_priv_self.captures(line).unwrap();
            let sender = caps.get(1).unwrap().as_str();
            let msg    = caps.get(2).map_or("", |m| m.as_str());
            let user   = parse_hostmask(sender);

            if msg.len() < 1 {
                debug(format!("PRIVMSG TOO SHORT {}", sender));
                return Event::PrivMsg;
            }

            // these are the bot commands with prefix
            if msg.starts_with(&self.config.prefix) {
                if !has_privilege(&user, &self.config.admins) {
                    self.send_privmsg(user.nick, MSG_NOPE);

                    return Event::Unprivileged;
                }
                if self.valid_command(msg, CMD_QUIT) {
                    let caps_cmd = re_cmd_quit.captures(msg).unwrap();
                    let quit_msg = caps_cmd.get(2).map_or("", |m| m.as_str());
                    debug(format!("EXITING {}", quit_msg));
                    self.send_privmsg(user.nick, MSG_IQUIT);

                    return Event::Quit(quit_msg.to_string());
                } else if self.valid_command(msg, CMD_JOIN) {
                    let caps_cmd = re_cmd_join.captures(msg).unwrap();
                    let channel = caps_cmd.get(1).map_or("", |m| m.as_str());
                    debug(format!("JOIN {}|{}|{}", sender, msg, channel));
                    if !channel.is_empty() {
                        self.send_join(channel);
                    }
                } else if self.valid_command(msg, CMD_PART) {
                    let caps_cmd = re_cmd_part.captures(msg).unwrap();
                    let channel = caps_cmd.get(1).map_or("", |m| m.as_str());
                    let part_msg = caps_cmd.get(3).map_or("", |m| m.as_str());
                    debug(format!("PART {}|{}|{}|{}", sender, msg, channel, part_msg));
                    self.send_part(channel, part_msg);
                } else if self.valid_command(msg, CMD_MODE) {
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
                } else if self.valid_command(msg, CMD_SAY) {
                    let caps_cmd = re_cmd_say.captures(msg).unwrap();
                    let channel = caps_cmd.get(1).map_or("", |m| m.as_str());
                    if channel.is_empty() {
                        return Event::CommandCancelled;
                    }
                    let say_msg = caps_cmd.get(2).map_or("", |m| m.as_str());
                    if say_msg.is_empty() {
                        return Event::CommandCancelled;
                    } else if say_msg.len() > 4 && &say_msg[0..4] == "/me " {
                        let ctcp = "ACTION";
                        debug(format!("ACT {}|{}|{}|{}", sender, msg, channel, &say_msg[4..]));
                        self.send_ctcp(channel, ctcp, &say_msg[4..])
                    } else {
                        debug(format!("SAY {}|{}|{}|{}", sender, msg, channel, say_msg));
                        self.send_privmsg(channel, say_msg);
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
                debug(format!("PRIVMSG_FROM {}|{}", sender, msg));

                return Event::PrivMsg;
            }

        } else if re_priv_chan.is_match(line) {
            let caps    = re_priv_chan.captures(line).unwrap();
            let sender  = caps.get(1).unwrap().as_str();
            let channel = caps.get(2).unwrap().as_str();
            let msg     = caps.get(5).map_or("", |m| m.as_str());
            let user    = parse_hostmask(sender);

            if msg.len() < 1 {
                debug(format!("PRIVMSG TOO SHORT {}", sender));
                return Event::PrivMsg;
            }

            let tpl_pat = ".*\\{(nick|ident|host|channel|msg)\\}.*";
            let tpl_re = Regex::new(tpl_pat).unwrap();
            let mut triggered = false;

            for reaction in self.config.reactions.clone() {
                if triggered {
                    continue;
                }
                let matcher     = reaction.trigger;
                let re_reaction = Regex::new(&matcher[..]).unwrap();
                let mut new_action = reaction.action.clone();
                if re_reaction.is_match(msg) {
                    triggered = true;
                    debug(format!("PRIVMSG_CHAN |({}) => {}|{}", matcher, new_action, msg));

                    if reaction.log.len() > 0 {
                        let mut log_file = OpenOptions::new().write(true).append(true).open(reaction.log).unwrap();
                        let mut log_msg = get_utc_time(false);
                        log_msg.push_str(" ");
                        log_msg.push_str(channel);
                        log_msg.push_str(" ");
                        log_msg.push_str(user.nick);
                        log_msg.push_str(" ");
                        log_msg.push_str(msg);
                        log_msg.push_str("\n");
                        debug(format!("Logging reaction: {}", log_msg));
                        log_file.write(log_msg.as_bytes());
                    }
                    let mut num: i32 = 0;
                    if reaction.occur > 0 {
                        let mut rng = rand::thread_rng();
                        num = rng.gen_range(0..=100);
                    }
                    if num < reaction.occur && reaction.action.len() > 0 {
                        if tpl_re.is_match(&reaction.action) {
                            let caps = tpl_re.captures(&reaction.action).unwrap();
                            let result = caps.get(1);
                            let what = caps.get(1).map_or(String::new(), |v| ["{", v.as_str(), "}"].join(""));
                            let replace = match result {
                                Some(a) => {
                                    match a.as_str() {
                                        "nick"    => user.nick,
                                        "ident"   => user.ident,
                                        "host"    => user.host,
                                        "channel" => channel,
                                        "msg"     => msg,
                                        _           => "",
                                    }
                                }
                                None => "",
                            };
                            new_action = new_action.replace(&what, replace);
                        }
                        self.send_privmsg(channel, &new_action);
                    }
                }
            }

            if !triggered {
               debug(format!("PRIVMSG_CHAN <{}>|{}", sender, line));
            }
        }

        Event::Unknown
    }

    fn valid_command(&mut self, input: &str, command: &str) -> bool {
        input.starts_with(&format!("{}{}", self.config.prefix, command))
    }
}
