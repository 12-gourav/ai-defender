# AgentGuard developer entry points. Every target is read-only with respect to the host
# except `build`, which writes to ./target. CI runs the same targets with --locked.

CARGO ?= cargo
LOCKED ?= --locked

.PHONY: all check build fmt fmt-check lint test ci audit deny doc clean

all: ci

check:
	$(CARGO) check --workspace --all-targets --all-features $(LOCKED)

build:
	$(CARGO) build --workspace --all-features $(LOCKED)

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

lint:
	$(CARGO) clippy --workspace --all-targets --all-features $(LOCKED) -- -D warnings

test:
	$(CARGO) test --workspace --all-features $(LOCKED)

# Dependency auditing needs cargo-deny and cargo-audit (user-space installs: `cargo install cargo-deny cargo-audit`).
deny:
	$(CARGO) deny check

audit:
	$(CARGO) audit

doc:
	$(CARGO) doc --workspace --no-deps $(LOCKED)

ci: fmt-check lint check test build

clean:
	$(CARGO) clean
