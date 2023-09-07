use cerith::{IRCStream, get_version, Config, Server, Reaction, DEFAULT_PORT};
use getopts::Options;
use std::env;
use std::io::Read;
use std::path::Path;
use std::fs::File;
use toml::Value;

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
        Err(f) => panic!("{}", f.to_string()),
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
    let mut servers = parse_servers(&val);

    // cli opts, overwriting the config
    let server_opt = match matches.opt_str("connect") {
        Some(s) => s,
        None => "".to_string(),
    };
    let port_opt = match matches.opt_str("port") {
        Some(s) => parse_int(s),
        None => DEFAULT_PORT,
    };

    // overwrite servers from config with CLI options
    if !server_opt.is_empty() {
        let server = Server::new(server_opt.to_string(), port_opt);
        servers = Vec::<Server>::new();
        servers.push(server);
    }

    for i in 0..servers.len() {
        let srv = &servers[i];
        let mut conn = match IRCStream::connect(srv) {
            Ok(s) => s,
            Err(_) => {
                println!("ERROR: Could not connect to server {}", srv);
                continue;
            }
        };

        conn.run(cfg.clone());
    }
}

fn read_config_file(filename: String) -> Value {
    // check and read config file
    let path = Path::new(&filename);
    let mut file = match File::open(&path) {
        Err(why) => panic!("ERROR: Couldn't open {}: {}", path.display(), &why),
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
                altnicks,
                parse_reactions(&val))
}

fn parse_servers(val: &Value) -> Vec<Server> {
    let mut servers = Vec::<Server>::new();
    for (k, v) in val["connection"].as_table().unwrap() {
        if !k.starts_with("server_") {
            continue;
        }
        match v.as_array() {
            Some(a) => {
                let host = match a[0].as_str() {
                    Some(s) => s.to_string(),
                    None => continue,
                };
                let port = match a[1].as_str() {
                    Some(s) => parse_int(s.to_string()),
                    None => continue,
                };
                let s = Server::new(host, port);
                servers.push(s);
            }
            None => continue,
        }
    }

    servers
}

fn parse_reactions(val: &Value) -> Vec<Reaction> {
    let mut reactions = Vec::<Reaction>::new();
    match val.get("reactions") {
        None => reactions,
        Some(xr) => {
            for (name, _section) in xr.as_table().unwrap() {
                let mut trigger = String::new();
                let mut action = String::new();
                let mut occur: i32 = 0;
                let mut log = String::new();
                for (k, v) in val["reactions"][name].as_table().unwrap() {
                    match v.as_str() {
                        Some(a) => {
                            if k == "trigger" {
                                trigger = a.to_string();
                            } else if k == "action" {
                                action = a.to_string();
                            } else if k == "occur" {
                                occur = parse_int(a.to_string());
                            } else if k == "log" {
                                log = a.to_string();
                            }
                        }
                        None => continue,
                    }
                }
                if trigger.len() > 0 && occur >= 0 && occur <= 100 {
                    let r = Reaction::new(trigger, action, occur, log);
                    reactions.push(r);
                }
            }

            reactions
        }
    }
}
