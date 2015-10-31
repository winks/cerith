extern crate getopts;
extern crate regex;
extern crate time;

use getopts::Options;
use regex::Regex;
use std::collections::HashSet;
use std::env;
use std::io::{Error,Read,Write};
use std::net::TcpStream;
use std::thread;

// General config stuff
static VERSION: &'static str = "0.1.0";
static NAME   : &'static str = "Cerith";
static ADMIN  : &'static str = "wink!fhtagn@cordelia.art-core.org";
static DEBUG  : bool = true;

// IRC config stuff
static NICKNAME: &'static str = "Cerith";
static REALNAME: &'static str = "Cerith";
static USERNAME: &'static str = "Cerith";
static USERMODE: i32 = 8;
static DEFAULT_PORT: i32 = 6667;
static CTCP_DELIM: &'static str = "\x01";

// Messages to be sent.
static MSG_QUIT : &'static str = "Fin.";
static MSG_GREET: &'static str = "Hello World!";
static MSG_IQUIT: &'static str = ":(";
static MSG_NOPE : &'static str = "You're not the boss of me.";

// Commands that are recognized
static CMD_PREFIX: &'static str = "!";
static CMD_QUIT: &'static str = "quit";
static CMD_JOIN: &'static str = "join";
static CMD_PART: &'static str = "part";
static CMD_SAY : &'static str = "say";
static CMD_MODE: &'static str = "mode";

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
    Quit,
    Unknown,
    Unprivileged,
}

fn debug(msg: String) {
    if DEBUG {
        println!("___ {}", msg);
    }
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn print_version() {
    println!("{}", get_version())
}

fn get_version() -> String {
    format!("{} {}", NAME, VERSION)
}

fn get_utc_time(msec: bool) -> String {
    let now = time::now_utc().to_timespec();
    let ss = now.sec.to_string();
    let ns = now.nsec.to_string();
    if msec {
        return ss + &ns[0..3];
    } else {
        return ss;
    }
}

fn get_local_time() -> String {
    let now = time::now();
    let fmt = format!("{}", now.rfc822());

    return fmt.replace(",", "");
}

fn parse_int(s: String) -> i32 {
    let n: Option<i32> = s.trim().parse().ok();
    let num = match n {
        Some(num) => num,
        None => 0,
    };

    return num;
}

fn parse_hostmask(s: &str) -> User {
    let re = Regex::new(r"^(.*)!(.*)@(.*)").unwrap();
    if re.is_match(s) {
        let x = re.captures(s).unwrap();
        let nick = x.at(1).unwrap();
        let ident = x.at(2).unwrap();
        let host = x.at(3).unwrap();

        return User{nick:nick, ident:ident, host:host};
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

    return input == full || &input[0..len] == full;
}

fn has_privilege(user: &User) -> bool {
    join_hostmask(&user) == ADMIN
}

// Adapted from https://github.com/mattnenterprise/rust-pop3/blob/20acb17197a7553d5a664725fe96df9fa5d042fd/src/pop3.rs
fn read_response(stream: &mut TcpStream) -> Vec<String> {
    //Carriage return
    let cr = 0x0d;
    //Line Feed
    let lf = 0x0a;
    let mut line_buffer: Vec<u8> = Vec::new();
    let mut all: Vec<String> = Vec::new();
    while line_buffer.len() < 2 || (line_buffer[line_buffer.len()-1] != lf && line_buffer[line_buffer.len()-2] != cr) {
        let byte_buffer: &mut [u8] = &mut [0];
        match stream.read(byte_buffer) {
            Ok(_) => {},
            Err(_) => println!("Error Reading!"),
        }
        line_buffer.push(byte_buffer[0]);
    }

    match String::from_utf8(line_buffer.clone()) {
        Ok(res) => {
            //println!("DEBUG {:?}", res);
            all.push(res);
            //line_buffer = Vec::new();
        },
        Err(_) => panic!("Failed to read the response")
    }

    all
}

fn send_raw(stream: &mut TcpStream, msg: &String) -> Result<(), Error> {
    let sent = stream.write_fmt(format_args!("{}", msg));
    debug(format!("S {:?} {:?}", msg, sent));

    sent
}

fn send_ctcp(stream: &mut TcpStream, to: &str, command: &str, msg: &str) {
    let delim = CTCP_DELIM.to_string();
    let ctcp = delim + command + " " + msg + CTCP_DELIM;
    let _ = send_privmsg(stream, to, &ctcp[..]);
}

fn send_ctcp_reply(stream: &mut TcpStream, to: &str, command: &str, msg: &str) {
    let delim = CTCP_DELIM.to_string();
    let ctcp = delim + command + " " + msg + CTCP_DELIM;
    let _ = send_notice(stream, to, &ctcp[..]);
}

fn send_join(stream: &mut TcpStream, channel: &str) {
    let _ = send_raw(stream, &(format!("JOIN {}\n", channel)));
}

fn send_mode(stream: &mut TcpStream, channel: &str, msg: &str) {
    let _ = send_raw(stream, &(format!("MODE {} {}\n", channel, msg)));
}

fn send_nick(stream: &mut TcpStream, msg: &str) {
    let _ = send_raw(stream, &(format!("NICK :{}\n", msg)));
}

fn send_notice(stream: &mut TcpStream, to: &str, msg: &str) {
    let _ = send_raw(stream, &(format!("NOTICE {} :{}\n", to, msg)));
}

fn send_part(stream: &mut TcpStream, channel: &str, msg: &str) {
    if msg.len() > 0 {
        let _ = send_raw(stream, &(format!("PART {} :{}\n", channel, msg)));
    } else {
        let _ = send_raw(stream, &(format!("PART {}\n", channel)));
    }
}

fn send_pong(stream: &mut TcpStream, msg: &str) {
    let _ = send_raw(stream, &(format!("PONG :{}\n", msg)));
}

fn send_privmsg(stream: &mut TcpStream, to: &str, msg: &str) {
    let _ = send_raw(stream, &(format!("PRIVMSG {} :{}\n", to, msg)));
}

fn send_user(stream: &mut TcpStream, name: &str, mode: i32, realname: &str) {
    let _ = send_raw(stream, &(format!("USER {} {} * :{}\n", name, mode, realname)));
}

fn send_quit(stream: &mut TcpStream, msg: &str) {
    let _ = send_raw(stream, &(format!("QUIT :{}\n", msg)));
}

fn handle_line(stream: &mut TcpStream, line: &str) -> Event {
    let event_priv = format!(":(.*) PRIVMSG {} :(.*)\r\n", NICKNAME);
    let event_ping = "^PING\\s+:(.*)";
    let event_motd = ".*End of MOTD command.*";

    let re_motd = Regex::new(&event_motd[..]).unwrap();
    let re_ping = Regex::new(&event_ping[..]).unwrap();
    let re_priv = Regex::new(&event_priv[..]).unwrap();

    let event_cmd_join = format!("{}{}\\s+(.*)", CMD_PREFIX, CMD_JOIN);
    let event_cmd_part = format!("{}{}\\s+(\\S+)(\\s+)?(.*)?", CMD_PREFIX, CMD_PART);
    let event_cmd_quit = format!("{}{}(\\s+)?(.*)?", CMD_PREFIX, CMD_QUIT);
    let event_cmd_say  = format!("{}{}\\s+(\\S+)\\s+(.+)", CMD_PREFIX, CMD_SAY);
    let event_cmd_mode = format!("{}{}\\s+(\\S+)\\s+(.+)", CMD_PREFIX, CMD_MODE);

    let re_cmd_join = Regex::new(&event_cmd_join[..]).unwrap();
    let re_cmd_part = Regex::new(&event_cmd_part[..]).unwrap();
    let re_cmd_quit = Regex::new(&event_cmd_quit[..]).unwrap();
    let re_cmd_say  = Regex::new(&event_cmd_say[..]).unwrap();
    let re_cmd_mode = Regex::new(&event_cmd_mode[..]).unwrap();

    if re_motd.is_match(line) {
        debug(format!("CONNECTED"));
        thread::sleep_ms(1000);

        send_privmsg(stream, ADMIN, MSG_GREET);

        return Event::Connected;
    } else if re_ping.is_match(line) {
        let payload = re_ping.captures(line).unwrap().at(1).unwrap();
        debug(format!("PONG {}", payload));
        send_pong(stream, payload);

        return Event::PingPong;
    } else if re_priv.is_match(line) {
        let caps   = re_priv.captures(line).unwrap();
        let sender = caps.at(1).unwrap();
        let msg    = caps.at(2).unwrap_or("");
        let user   = parse_hostmask(sender);

        if msg.len() < 1 {
            debug(format!("PRIVMSG TOO SHORT {}", sender));
            return Event::PrivMsg;
        }

        // these are the bot commands with prefix
        if msg.chars().nth(0) == CMD_PREFIX.chars().nth(0) {
            if ! has_privilege(&user) {
                send_privmsg(stream, user.nick, MSG_NOPE);

                return Event::Unprivileged;
            }
            if is_command(msg, CMD_QUIT) {
                let caps_cmd = re_cmd_quit.captures(msg).unwrap();
                let quit_msg = caps_cmd.at(2).unwrap_or("");
                debug(format!("EXITING {}", quit_msg));
                send_privmsg(stream, user.nick, MSG_IQUIT);

                return Event::Quit;
            } else if is_command(msg, CMD_JOIN) {
                let caps_cmd = re_cmd_join.captures(msg).unwrap();
                let channel  = caps_cmd.at(1).unwrap();
                debug(format!("JOIN {}|{}|{}", sender, msg, channel));
                send_join(stream, channel);
            } else if is_command(msg, CMD_PART) {
                let caps_cmd = re_cmd_part.captures(msg).unwrap();
                let channel  = caps_cmd.at(1).unwrap();
                let part_msg = caps_cmd.at(3).unwrap_or("");
                debug(format!("PART {}|{}|{}|{}", sender, msg, channel, part_msg));
                send_part(stream, channel, part_msg);
            } else if is_command(msg, CMD_MODE) {
                let caps_cmd = re_cmd_mode.captures(msg).unwrap();
                let channel  = caps_cmd.at(1).unwrap();
                let rest     = caps_cmd.at(2).unwrap_or("");

                if rest.len() < 2 {
                    let lists: HashSet<_> = [
                        "I", // invitations masks
                        "e", // exemptions masks
                    ].iter().cloned().collect();

                    if rest.len() == 1 && lists.contains(rest) {
                        debug(format!("CHANMODE L {}|{}|{}|{}", sender, msg, channel, rest));
                        send_mode(stream, channel, rest);

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
                let arity_0: HashSet<_> = [
                    "c", // no colors
                    "C", // no ctcp
                    "m", // moderated
                    "n", // no external messages
                    "r", // registered users only
                    "R", // registered users only
                    "s", // secret
                    "S", // strip colors
                    "t", // topic lock
                    "z", // secure joins only
                ].iter().cloned().collect();

                let arity_1: HashSet<_> = [
                    "b", // ban
                    "h", // half-op
                    "k", // channel key
                    "l", // channel limit
                    "o", // operator
                    "v", // voice
                ].iter().cloned().collect();

                if arity_0.contains(second) {
                    let mode = &rest[0..2];
                    debug(format!("CHANMODE 0 {}|{}|{}|{}", sender, msg, channel, mode));
                    send_mode(stream, channel, mode);
                } else if arity_1.contains(second) {
                    let mode = &rest[0..2];
                    if rest.len() < 4 {
                        return Event::CommandCancelled;
                    }
                    let arg = &rest[3..].trim();
                    debug(format!("CHANMODE 1 {}|{}|{}|{}|{}", sender, msg, channel, mode, arg));
                    send_mode(stream, channel, &rest[..]);
                } else {
                    debug(format!("CHANMODE ? {}|{}|{}", sender, msg, channel));
                    //send_privmsg(stream, channel, &say_msg2[..]);
                    return Event::CommandCancelled;
                }
            } else if is_command(msg, CMD_SAY) {
                let caps_cmd = re_cmd_say.captures(msg).unwrap();
                let channel  = caps_cmd.at(1).unwrap();
                let say_msg  = caps_cmd.at(2).unwrap_or("");
                if say_msg.len() > 0 {
                    if say_msg.len() > 4 && &say_msg[0..4] == "/me " {
                        let ctcp = "ACTION";
                        debug(format!("ACT {}|{}|{}|{}", sender, msg, channel, &say_msg[4..]));
                        send_ctcp(stream, channel, ctcp, &say_msg[4..])
                    } else {
                        debug(format!("SAY {}|{}|{}|{}", sender, msg, channel, say_msg));
                        send_privmsg(stream, channel, say_msg);
                    }
                } else {
                    return Event::CommandCancelled;
                }
            } else {
                debug(format!("CMD {}|{}", sender, msg));
            }

            return Event::Command;
        } else if &msg[0..1] == "\x01" {
            // CTCP stuff
            let len = msg.len();
            if len < 3 || &msg[len-1..len] != "\x01" {
                debug(format!("PRIVMSG CTCP:FAIL {}|{}", sender, msg));
                return Event::PrivMsg;
            }
            let payload = &msg[1..len-1];
            debug(format!("PRIVMSG CTCP:OK {}|{}", sender, payload));

            if payload == "VERSION" {
                let command = "VERSION";
                let reply = get_version();
                debug(format!("PRIVMSG CTCP:{} {}|{}", command, sender, reply));
                send_ctcp_reply(stream, sender, command, &reply[..]);

                return Event::CTCP;
            } else if payload == "TIME" {
                let command = "TIME";
                let reply = get_local_time();
                debug(format!("PRIVMSG CTCP:{} {}|{}", command, sender, reply));
                send_ctcp_reply(stream, sender, command, &reply[..]);

                return Event::CTCP;
            } else if &payload[0..4] == "PING" {
                if payload.len() < 6 {
                    return Event::Unknown;
                }
                //let rest = &payload[5..];
                let command = "PING";

                let reply = get_utc_time(true);
                debug(format!("PRIVMSG CTCP:{} {}|{}", command, sender, reply));
                send_ctcp_reply(stream, sender, command, &reply[..]);
            }
        } else {
            debug(format!("PRIVMSG {}|{}", sender, msg));

            return Event::PrivMsg;
        }
    }
    return Event::Unknown;
}

fn connect(host: &str, port: i32) {
    let conn_string = format!("{}:{}", host, port);
    let mut tcp_stream = TcpStream::connect(&conn_string[..]).unwrap();

    let mut rcvd;
    let mut initialized = false;

    loop {
        rcvd = read_response(&mut tcp_stream);
        let line = &rcvd[0][..];
        debug(format!("R {:?}", line));

        if !initialized {
            send_nick(&mut tcp_stream, NICKNAME);
            send_user(&mut tcp_stream, USERNAME, USERMODE, REALNAME);
            initialized = true;
            continue;
        }

        let event = handle_line(&mut tcp_stream, line);
        match event {
            Event::Quit => {
                debug(format!("Event::Quit"));
                break
            },
            Event::Connected => debug(format!("Event::Connected")),
            _ => ()
        }
    }

    // shutting down
    thread::sleep_ms(200);
    send_quit(&mut tcp_stream, MSG_QUIT);
    println!("");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
    opts.optflag("v", "version", "print the version");

    opts.optopt("c", "connect", "Autoconnect server", "SERVER");
    opts.optopt("p", "port", "Autoconnect port", "PORT");

    let matches = match opts.parse(&args[1..]) {
        Ok(m)  => { m }
        Err(f) => { panic!(f.to_string()) }
    };
    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }
    if matches.opt_present("v") {
        print_version();
        return;
    }
    let server = match matches.opt_str("c") {
        Some(s) => s,
        None => { panic!("No server given.")}
    };
    let mut port = match matches.opt_str("p") {
        Some(s) => parse_int(s),
        None => 0,
    };
    if port < 1 {
        port = DEFAULT_PORT
    }

    connect(&server, port);
}
