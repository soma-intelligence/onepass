.PHONY: check fmt-check test lint deny audit vet sbom fuzz miri

# Seconds per fuzz target (override: make fuzz FUZZ_SECONDS=300).
FUZZ_SECONDS ?= 60
# Pinned nightly for fuzz and Miri (same date as .github/workflows/core.yml).
NIGHTLY ?= nightly-2026-10-20
FUZZ_TARGETS = blob_open signed_manifest account_params item_record signature_verify otpauth_parse reference_parse import_csv import_1pux import_bitwarden_json import_enpass_json import_keepass_xml import_cxf import_text archive_open hibp_range site_directory mcp_line ssh_agent_frame

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

# Supply-chain audits (supply-chain/). Not part of `check`: it fetches the
# imported audit sets from the network. CI runs it.
vet:
	cargo vet

# CycloneDX SBOM per workspace crate, written next to each crate then moved to
# target/sbom/. Needs cargo-cyclonedx (cargo install --locked cargo-cyclonedx).
sbom:
	rm -rf target/sbom && mkdir -p target/sbom
	cargo cyclonedx --format json --spec-version 1.5 --all
	for f in $$(find . -path ./target -prune -o -name '*.cdx.json' -print); do mv "$$f" target/sbom/; done

# Needs the nightly toolchain and cargo-fuzz (cargo install cargo-fuzz).
fuzz:
	for t in $(FUZZ_TARGETS); do \
		cargo +$(NIGHTLY) fuzz run $$t -- -max_total_time=$(FUZZ_SECONDS) || exit 1; \
	done

# Needs the nightly toolchain with Miri (rustup toolchain install $(NIGHTLY) --component miri,rust-src).
# mlock and sysconf are stubbed under cfg(miri). Pool pages are never freed
# by design, hence the leak check is off.
miri:
	MIRIFLAGS="-Zmiri-ignore-leaks" cargo +$(NIGHTLY) miri test -p onepass-core --lib crypto::locked
