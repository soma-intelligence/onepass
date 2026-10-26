.PHONY: test lint deny audit

test:
	cargo test --workspace

lint:
	cargo clippy --workspace --all-targets -- -D warnings

deny:
	cargo deny check

audit:
	cargo audit
