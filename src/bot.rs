extern crate cerith;
extern crate getopts;

use getopts::Options;
use std::env;
use cerith::{IRCStream, get_version};

static DEFAULT_PORT: i32 = 6667;

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn print_version() {
    println!("{}", get_version())
}

fn parse_int(s: String) -> i32 {
    let n: Option<i32> = s.trim().parse().ok();
    let num = match n {
        Some(num) => num,
        None => 0,
    };

    return num;
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
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };
    if matches.opt_present("help") {
        print_usage(&program, opts);
        return;
    }
    if matches.opt_present("version") {
        print_version();
        return;
    }
    let server = match matches.opt_str("connect") {
        Some(s) => s,
        None => panic!("No server given."),
    };
    let mut port = match matches.opt_str("port") {
        Some(s) => parse_int(s),
        None => 0,
    };
    if port < 1 {
        port = DEFAULT_PORT
    }

    let mut conn = match IRCStream::connect(&server.to_owned()[..], port) {
        Ok(s) => s,
        Err(e) => panic!("{}", e),
    };
    conn.run();
}
