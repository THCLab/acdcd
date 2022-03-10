#!/bin/bash

set -e
trap 'kill $(jobs -p)' EXIT

require_file() {
    if [ ! -f "$0" ]; then
        echo "Missing $0"
        exit 1
    fi
}

print_step() {
    echo
    echo
    echo "###"
    echo "###" "$@"
    echo "###"
}

require_file ../dkms-resolver/Cargo.toml
require_file ../keri-witness-http/Cargo.toml

print_step "Starting resolver"
pushd ../dkms-resolver || exit 1
cargo build
cargo run &
popd || exit 1
sleep 1

print_step "Starting witness"
pushd ../keri-witness-http || exit 1
cargo build
cargo run -- -k 2547a4d5b0ddbe55d04b1258aadd3fed3000f561f8574e2f246c59ef1a36f027 &
popd || exit 1
sleep 1

print_step "Starting TDA"
cargo build
cargo run &
sleep 1

print_step "Creating attestation..."
curl http://localhost:13434/attestations/create -H 'Content-Type:application/json' \
    -d '{"v":"ACDC10JSON00011c_","i":"alice","s":"E46jrVPTzlSkUPqGGeIZ8a8FWS7a6s4reAXRZOkogZ2A","a":{},"p":[],"r":[]}' \
    >/tmp/attest.txt
sleep 1

print_step "Printing attestation..."
cat /tmp/attest.txt
sleep 1

print_step "Verifying attestation..."
curl http://localhost:13434/attestations -H 'Content-Type:text/plain' -d @/tmp/attest.txt
sleep 1

print_step "Listing attestations..."
curl http://localhost:13434/attestations
sleep 1
