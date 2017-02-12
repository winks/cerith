extern crate cerith;
extern crate getopts;
extern crate toml;

use cerith::{IRCStream, get_version, Config};
use getopts::Options;
use std::env;
use std::io::Read;
use std::path::Path;
use std::fs::File;
use toml::Value;

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

    match n {
        Some(num) => num,
        None => 0,
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
    opts.optflag("v", "version", "print the version");

    opts.optopt("c", "connect", "Autoconnect server", "SERVER");
    opts.optopt("p", "port", "Autoconnect port", "PORT");
    opts.optopt("f", "file", "Config file", "FILE");

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
    let filename = match matches.opt_str("file") {
        Some(s) => s,
        None => {
            print_usage(&program, opts);
            return;
        }
    };

    let val = read_config_file(filename);
    let cfg = parse_toml(&val);

    let mut server = match val["connection"]["server"].as_str() {
        Some(s) => s.to_string(),
        None => "".to_string(),
    };
    let mut port = match val["connection"]["port"].as_integer() {
        Some(s) => s as i32,
        None => 0,
    };

    // cli opts, overwriting the config
    let server_opt = match matches.opt_str("connect") {
        Some(s) => s,
        None => panic!("No server given."),
    };
    let port_opt = match matches.opt_str("port") {
        Some(s) => parse_int(s),
        None => 0,
    };

    if port < 1 {
        if port_opt > 0 {
            port = port_opt
        } else {
            port = DEFAULT_PORT
        }
    }
    if server.is_empty() {
        server = server_opt
    }

    let mut conn = match IRCStream::connect(server, port) {
        Ok(s) => s,
        Err(e) => panic!("{}", e),
    };

    conn.run(cfg);
}

fn read_config_file(filename: String) -> Value {
    // check and read config file
    let path = Path::new(&filename);
    let mut file = match File::open(&path) {
        Err(why) => panic!("couldn't open {}: {}", path.display(), &why),
        Ok(file) => file,
    };

    let mut contents = String::new();
    let _ = file.read_to_string(&mut contents);

    contents.parse::<Value>().unwrap()
}

fn parse_toml(val: &Value) -> Config {
    // config parameters from config file
    let nickname = match val["bot"]["nickname"].as_str() {
        Some(s) => s.to_string(),
        None => "".to_string(),
    };
    let username = match val["bot"]["username"].as_str() {
        Some(s) => s.to_string(),
        None => "".to_string(),
    };
    let realname = match val["bot"]["realname"].as_str() {
        Some(s) => s.to_string(),
        None => "".to_string(),
    };
    let usermode = match val["bot"]["usermode"].as_str() {
        Some(s) => {
            let mut u = 0;
            if s.contains('i') {
                u += 8
            }
            if s.contains('w') {
                u += 4
            }
            u
        }
        None => -1,
    };

    let prefix = match val["misc"]["prefix"].as_str() {
        Some(s) => s.to_string(),
        None => "".to_string(),
    };

    let mut admins = Vec::new();
    let mut altnicks = Vec::new();

    match val["bot"]["admins"].as_array() {
        Some(ax) => {
            let v = Vec::<String>::new();
            for a in ax {
                let a2 = match a.as_str() {
                    Some(a2) => a2.to_string(),
                    None => "".to_string(),
                };
                if !a2.is_empty() {
                    admins.push(a2);
                }
            }
            v
        }
        None => Vec::<String>::new(),
    };

    match val["bot"]["altnicks"].as_array() {
        Some(ax) => {
            let v = Vec::<String>::new();
            for a in ax {
                let a2 = match a.as_str() {
                    Some(a2) => a2.to_string(),
                    None => "".to_string(),
                };
                if !a2.is_empty() {
                    altnicks.push(a2);
                }
            }
            v
        }
        None => Vec::<String>::new(),
    };

    Config::new(nickname,
                username,
                realname,
                usermode,
                prefix,
                admins,
                altnicks)
}
