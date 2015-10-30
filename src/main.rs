extern crate getopts;
extern crate regex;

use getopts::Options;
use regex::Regex;
use std::env;
use std::io::{Error,Read,Write};
use std::net::TcpStream;
use std::thread;

// General config stuff
static VERSION: &'static str = "0.1.0";
static NAME   : &'static str = "Cerith";
static ADMIN  : &'static str = "wink";
static DEBUG  : bool = true;

// IRC config stuff
static NICKNAME: &'static str = "Cerith";
static REALNAME: &'static str = "Cerith";
static USERNAME: &'static str = "Cerith";
static USERMODE: i32 = 8;
static DEFAULT_PORT: i32 = 6667;

// Messages to be sent.
static MSG_QUIT : &'static str = "Fin.";
static MSG_GREET: &'static str = "Hello World!";
static MSG_IQUIT: &'static str = ":(";
static MSG_NOPE: &'static str = "You're not the boss of me.";

// Commands that are recognized
static CMD_PREFIX: &'static str = "!";
static CMD_QUIT: &'static str = "quit";

struct User<'a> {
    nick: &'a str,
    ident: &'a str,
    host: &'a str,
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
    print!("{} {}\n", NAME, VERSION)
}

fn parse_int(s: String) -> i32 {
    let n: Option<i32> = s.trim().parse().ok();
    let num = match n {
        Some(num) => num,
        None => 0,
    };

    return num;
}

fn split_hostmask(s: &str) -> User {
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

// From https://github.com/mattnenterprise/rust-pop3
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
    println!("S {:?} {:?}", msg, sent);

    sent
}

fn send_privmsg(stream: &mut TcpStream, to: &str, msg: &str) {
    let _ = send_raw(stream, &(format!("PRIVMSG {} :{}\n", to, msg)));
}

fn send_pong(stream: &mut TcpStream, msg: &str) {
    let _ = send_raw(stream, &(format!("PONG :{}\n", msg)));
}

fn send_nick(stream: &mut TcpStream, msg: &str) {
    let _ = send_raw(stream, &(format!("NICK :{}\n", msg)));
}

fn send_user(stream: &mut TcpStream, name: &str, mode: i32, realname: &str) {
    let _ = send_raw(stream, &(format!("USER {} {} * :{}\n", name, mode, realname)));
}

fn send_quit(stream: &mut TcpStream, msg: &str) {
    let _ = send_raw(stream, &(format!("QUIT :{}\n", msg)));
}

fn connect(host: &str, port: i32) {
    let event_priv = format!(":(.*) PRIVMSG {} :(.*)\r\n", NICKNAME);
    let event_ping = r"^PING\s+:(.*)";
    let event_motd = ".*End of MOTD command.*";

    let re_motd = Regex::new(&event_motd[..]).unwrap();
    let re_ping = Regex::new(&event_ping[..]).unwrap();
    let re_priv = Regex::new(&event_priv[..]).unwrap();

    let conn_string = format!("{}:{}", host, port);
    let mut tcp_stream = TcpStream::connect(&conn_string[..]).unwrap();

    let mut rcvd;
    rcvd = read_response(&mut tcp_stream);
    println!("R {:?}", rcvd);

    send_nick(&mut tcp_stream, NICKNAME);
    send_user(&mut tcp_stream, USERNAME, USERMODE, REALNAME);

    loop {
        rcvd = read_response(&mut tcp_stream);
        let line = &rcvd[0][..];
        println!("R {:?}", line);

        if re_motd.is_match(line) {
            debug(format!("CONNECTED"));
            thread::sleep_ms(1000);

            send_privmsg(&mut tcp_stream, ADMIN, MSG_GREET);
        } else if re_ping.is_match(line) {
            let payload = re_ping.captures(line).unwrap().at(1).unwrap();
            debug(format!("PONG {}", payload));
            send_pong(&mut tcp_stream, payload);
        } else if re_priv.is_match(line) {
            let caps   = re_priv.captures(line).unwrap();
            let sender = caps.at(1).unwrap();
            let msg    = caps.at(2).unwrap();
            let user   = split_hostmask(sender);

            if msg.chars().nth(0) == CMD_PREFIX.chars().nth(0) {
                if msg == CMD_PREFIX.to_string() + CMD_QUIT {
                    if user.nick == ADMIN {
                        debug(format!("EXITING"));
                        send_privmsg(&mut tcp_stream, user.nick, MSG_IQUIT);
                        // shutting down
                        break;
                    } else {
                        send_privmsg(&mut tcp_stream, user.nick, MSG_NOPE);
                    }
                } else {
                    debug(format!("CMD {} {}", sender, msg));
                }
            } else {
                debug(format!("PRIVMSG {} {}", sender, msg));
            }
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
