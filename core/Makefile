.PHONY: check fmt-check test lint deny audit vet sbom fuzz miri quick nextest

# Seconds per fuzz target (override: make fuzz FUZZ_SECONDS=300).
FUZZ_SECONDS ?= 60
# Pinned nightly for fuzz and Miri (same date as .github/workflows/core.yml).
NIGHTLY ?= nightly-2026-10-20
FUZZ_TARGETS = blob_open signed_manifest account_params item_record signature_verify otpauth_parse reference_parse import_csv import_1pux import_bitwarden_json import_enpass_json import_keepass_xml import_cxf import_text archive_open hibp_range site_directory mcp_line ssh_agent_frame mailbox_message mailbox_signature_input enroll_ticket remote_message contact_frames sync_home enroll_request

check: fmt-check lint test deny

fmt-check:
	cargo fmt --all --check

test:
	cargo test --workspace

# Fast local loop (needs cargo-nextest: brew install cargo-nextest). Runs only
# the crates changed since origin/main (QUICK_BASE overrides it; QUICK_CRATES
# names them directly), with the dev KDF, per-test timeouts from
# .config/nextest.toml, and at low priority so the Mac stays usable. Source
# ../scripts/dev-env.sh first for the shared sccache cache and the job cap.
QUICK_BASE ?= origin/main
QUICK_CRATES ?= $(shell git diff --name-only $(QUICK_BASE) -- . 2>/dev/null \
	| sed -n 's|^core/\(onepass-[a-z0-9-]*\)/.*|\1|p' | sort -u)

quick:
	@if [ -z "$(QUICK_CRATES)" ]; then echo "quick: no crate changed since $(QUICK_BASE)"; exit 0; fi
	@echo "quick: $(QUICK_CRATES)"
	@with=""; without=""; \
	for c in $(QUICK_CRATES); do \
		if [ "$$c" = onepass-core ] || grep -q '^onepass-core' $$c/Cargo.toml; then with="$$with -p $$c"; \
		else without="$$without -p $$c"; fi; \
	done; \
	if [ -n "$$with" ]; then nice -n 10 cargo nextest run $$with --features onepass-core/dev-fast-kdf || exit 1; fi; \
	if [ -n "$$without" ]; then nice -n 10 cargo nextest run $$without || exit 1; fi

# The whole workspace through nextest: same tests as `make test`, with the
# per-test timeouts.
nextest:
	nice -n 10 cargo nextest run --workspace --features onepass-core/dev-fast-kdf

lint:
	cargo clippy --workspace --all-targets -- -D warnings

deny:
	cargo deny check

audit:
	cargo audit

# Supply-chain audits (supply-chain/), against the imported audit sets in
# supply-chain/imports.lock, as CI runs it. `cargo vet regenerate imports`
# refreshes them from the network.
vet:
	cargo vet --locked

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
