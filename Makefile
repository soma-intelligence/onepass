# Root targets. The Rust core has its own core/Makefile.

.PHONY: formal formal-clean

# Runs every ProVerif model and checks the results against formal/expected.txt.
# PROVERIF overrides the binary, FORMAL_TIMEOUT the per file limit (seconds).
formal:
	formal/run.sh

formal-clean:
	rm -rf formal/out
