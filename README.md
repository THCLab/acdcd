# ACDCD

```txt
USAGE:
    tda-deamon [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --api-port <api-port>          Daemon API listen port [default: 13434]
    -d, --kel-db-path <kel-db-path>     [default: controller_db]
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
    "v":"ACDC10JSON00011c_",
    "i":"DFoXDOClySJq5nvWKHXKRUYF8-SUHHR53Xugl4YdY9RM","s":"E46jrVPTzlSkUPqGGeIZ8a8FWS7a6s4reAXRZOkogZ2A",
    "a":{},
    "p":[],
    "r":[],
    "d":"EIxvZcjD9GaxlWeEUrPmiglmUqPnKQSKOm6NyVCuFS88"
}-0K-AABAAbn6wxKnkerdoly2yqK6GFQ0UeYMxC-uuLAvs2_TjRZe69f3aW15zY_7AxutVwUuess5WQmwrBrS7DIRGb0JKCA
```

### Listing attestations

```http
GET /attestations HTTP/1.1
```

## Example

```sh
# Start two tda instances
cargo run -- -d alice.db --api-port 10101 &
cargo run -- -d bob.db --api-port 10201 &

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
