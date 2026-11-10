# Run CI's Format, Clippy and Test jobs as .github/workflows/ci.yml does
check:
    cargo fmt --all -- --check
    cargo clippy --quiet --all-targets --all-features --workspace --exclude chat-cli -- -D warnings
    cargo build --quiet --workspace --exclude chat-cli --exclude embedded-logos-delivery
    cargo check --quiet --workspace --exclude chat-cli --exclude embedded-logos-delivery --exclude integration_tests_core
    cargo test --quiet --workspace --exclude chat-cli --exclude embedded-logos-delivery

# Run the CI smoketest: chat-cli's startup path against a mock registry.
smoketest name="ci-test":
    #!/usr/bin/env bash
    set -euo pipefail

    # The mock registry stands in for the account and keypackage store the
    # client registers with on startup. It validates nothing, so this proves
    # the client starts, registers and exits — not that the protocol is right.
    #
    # CI wraps the build and the run in `nix develop` so both link against the
    # same Nix glibc as the prebuilt liblogosdelivery. Here you get the shell
    # you are in: run it inside `nix develop`, or let chat-cli's build.rs build
    # the library through nix on its own.

    # The port the mock listens on: see .github/scripts/mock-registry.py.
    url="http://127.0.0.1:18080"

    # A CI runner starts empty; give the run the same. The mock keeps its
    # records in memory, so a database left by an earlier run holds an
    # installation this registry has never heard of, and the client refuses to
    # start on an endorsement nothing can confirm.
    data="target/smoketest"
    rm -rf "$data"

    cargo build --release -p chat-cli

    # Refuse the port to anything else: a mock that cannot bind leaves
    # whatever already owns it answering in its place, and the client then
    # fails on a stranger's records in a way that reads like a protocol bug.
    if curl -s -o /dev/null --max-time 1 "$url/"; then
        echo "something is already listening on $url; stop it and retry" >&2
        lsof -nP -iTCP:18080 -sTCP:LISTEN >&2 || true
        exit 1
    fi

    python3 .github/scripts/mock-registry.py &
    registry=$!
    trap 'kill "$registry" 2>/dev/null || true' EXIT

    for _ in $(seq 1 50); do
        if curl -s -o /dev/null "$url/"; then break; fi
        sleep 0.2
    done

    ./target/release/chat-cli \
        --name {{ name }} \
        --smoketest \
        --data "$data" \
        --registry-url "$url"

ci: check smoketest

# Load local just file after so it overwrites repo defined commands
# Use [Default] to set the default command in local file
import? 'justfile.local'
