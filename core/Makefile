.PHONY: check fmt-check test lint deny audit fuzz

# Seconds per fuzz target (override: make fuzz FUZZ_SECONDS=300).
FUZZ_SECONDS ?= 60
FUZZ_TARGETS = blob_open signed_manifest account_params item_record signature_verify otpauth_parse reference_parse

check: fmt-check lint test deny

fmt-check:
	cargo fmt --all --check

test:
	cargo test --workspace

lint:
	cargo clippy --workspace --all-targets -- -D warnings

deny:
	cargo deny check

audit:
	cargo audit

# Needs the nightly toolchain and cargo-fuzz (cargo install cargo-fuzz).
fuzz:
	for t in $(FUZZ_TARGETS); do \
		cargo +nightly fuzz run $$t -- -max_total_time=$(FUZZ_SECONDS) || exit 1; \
	done
