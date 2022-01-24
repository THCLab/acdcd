# Tda-deamon

```txt
USAGE:
    tda-deamon [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --api-port <api-port>          Daemon API listen port [default: 13434]
    -d, --kel-db-path <kel-db-path>     [default: controller_db]
    -r <resolver-address>               [default: http://127.0.0.1:9599]
    -t <witness-threshold>              [default: 0]
    -w <witnesses>...                   [default: None]
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

## Notes about interactions between tda-deamon, [witness](https://github.com/THCLab/keri-witness-http) and [resolver](https://github.com/THCLab/keri-resolver).

### Run

1. Start the resolver. You can set the listening port with `--api-port` flag, the default is 9599.

2. Start witnesses. It will create the default database file `witness_db` and will use default port 3030. If you want to use more than one witness, each witness should have a separate database and port. It can be set with console arguments. When you start the witness, it will show you its identifier. 
**Note**: If you changed the resolver listening port in the previous step, you should set it for all of your witnesses using `-r` flag.

3. Start tda. You can set witnesses used by tda using `-w` flag, their identifiers can be taken from the previous step. You can also set a witness threshold, default there are no witnesses and the threshold is 0. 
Tda will generate its inception event and will send it to the designated witnesses. When witnesses collect enough receipts, they will publish the controller's current key config in the resolver.
