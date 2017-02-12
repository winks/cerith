build:
	cargo build

release:
	cargo build --release

check:
	rustup run nightly cargo clippy

fmt:
	cargo fmt

nightly:
	rustup override set nightly

stable:
	rustup override set 1.15.1

clippy:
	make nightly
	cargo clippy
	make stable