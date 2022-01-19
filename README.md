# ACDCD

```txt
USAGE:
    acdcd [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --api-port <api-port>                Daemon API listen port [default: 13434]
        --bootstrap-addr <bootstrap-addr>    DHT bootstrap IP address
        --dht-port <dht-port>                DHT listen port [default: 13435]
    -k, --priv-key-path <priv-key-path>      Path to private key PEM file. If it doesn't exist it will be generated with
                                             a random key [default: acdcd.key]
    -u, --user-id <user-id>                  Current user ID

```

## API

### Creating attestation

Creates a new attestation signed with current priv key.
The issuer field (`i`) should be the same as current user ID (`--user-id` option).

```http
POST /attestations/create HTTP/1.1
Content-Type: application/json

{
    "a": {},
    "i": "issuer",
    "p": [],
    "r": [],
    "s": "E46jrVPTzlSkUPqGGeIZ8a8FWS7a6s4reAXRZOkogZ2A",
    "v": "ACDC10JSON00011c_"
}
```

### Receiving attestation

Receives an already created attestation and verifies it.

```http
POST /attestations HTTP/1.1
Content-Type: text/plain

{
    "v": "ACDC10JSON00011c_",
    "i": "issuer",
    "s": "E46jrVPTzlSkUPqGGeIZ8a8FWS7a6s4reAXRZOkogZ2A",
    "a": {},
    "p": [],
    "r": [],
    "d": "E1aoCawdBMPw0TfHtuHgQvfu5AzAHWUadzv9CCtUhZlI"
}-0BIReyL7bwCTXwuNNKvIb2wZUyqKiBevHTcZvPyznPFso62xApCmkxZmSyXGvYK9eUUtf3aQofAG/rcN69bav4Dg==
```

### Listing attestations

```http
GET /attestations HTTP/1.1
```

## Example

```sh
# Start two acdcd instances
cargo run -- -u alice -k alice.key --api-port 10101 --dht-port 10102 &
cargo run -- -u bob -k bob.key --api-port 10201 --dht-port 10202 --bootstrap-addr 127.0.0.1:10102 &

# Create attestation as Alice
curl http://localhost:10101/attestations/create -H 'Content-Type:application/json' \
    -d '{"v":"ACDC10JSON00011c_","i":"alice","s":"E46jrVPTzlSkUPqGGeIZ8a8FWS7a6s4reAXRZOkogZ2A","a":{},"p":[],"r":[]}' \
    > attest.txt

# Preview attestation data
cat attest.txt

# Verify Alice's attestation as Bob
curl http://localhost:10201/attestations -H 'Content-Type:text/plain' -d @attest.txt

# List Bob's received attestations
curl http://localhost:10201/attestations
```
