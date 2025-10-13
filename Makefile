.PHONY: fmt lint test test-release test-all-features run-cli ci

fmt:
	cargo fmt

lint: fmt
	cargo clippy --all-targets --all-features -- -D warnings
	$(MAKE) test-all-features

test:
	cargo test

test-release:
	cargo test --release

test-all-features:
	cargo test --all-features

run-cli:
	cargo run --bin mailcheck-cli --

# (optionnel) pipeline complet
ci: fmt
	cargo clippy --all-targets --all-features -- -D warnings
	cargo test
	cargo test --all-features
	cargo test --release
