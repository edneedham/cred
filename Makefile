.PHONY: check

check:
	cargo fmt --all -- --check
	cargo test

