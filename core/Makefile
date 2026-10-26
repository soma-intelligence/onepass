.PHONY: check fmt-check test lint deny audit fuzz miri

# Seconds per fuzz target (override: make fuzz FUZZ_SECONDS=300).
FUZZ_SECONDS ?= 60
FUZZ_TARGETS = blob_open signed_manifest account_params item_record signature_verify otpauth_parse reference_parse import_csv import_1pux import_bitwarden_json import_keepass_xml import_cxf import_text archive_open hibp_range site_directory mcp_line ssh_agent_frame

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

# Needs the nightly toolchain with Miri (rustup +nightly component add miri).
# mlock and sysconf are stubbed under cfg(miri). Pool pages are never freed
# by design, hence the leak check is off.
miri:
	MIRIFLAGS="-Zmiri-ignore-leaks" cargo +nightly miri test -p onepass-core --lib crypto::locked
