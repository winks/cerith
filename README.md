# Cerith

### Intro

An IRC bot written in [Rust](https://www.rust-lang.org). Experimental and flawed.

### Howto

```
cargo build --release
./target/release/cerith -c SERVER [-p PORT]
# or
./target/release/cerith -f FILE.toml
```

### Commands

  * `!join #channel`
  * `!part #channel MESSAGE`
  * `!say #channel MESSAGE`
  * `!mode #channel +...`
  * `!mode #channel -...`
  * `!quit`

### Thanks

Inspired by [rust-pop3](https://github.com/mattnenterprise/rust-pop3/).

### License

MIT
