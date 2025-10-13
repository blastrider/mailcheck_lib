.PHONY: fmt lint test test-release run-cli

fmt:
	cargo fmt

lint: fmt
	cargo clippy --all-targets --all-features -- -D warnings

test:
	cargo test

test-release:
	cargo test --release

run-cli:
	cargo run --bin mailcheck-cli --
