# ACDCD

```txt
USAGE:
    acdcd [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -p, --port <port>                 Daemon API port [default: 13434]
    -k, --priv-key <priv-key-path>    Path to private key PEM file. If it doesn't exist it will be generated with a
                                      random key [default: acdcd.key]
    -K, --pub-keys <pub-keys-path>    Path to public keys JSON file. The file should contain a map of user IDs and their
                                      base64-encoded ED25519 public keys [default: pub_keys.json]
```

## API

### Creating attestation

Creates a new attestation signed with current priv key

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


HTTP/1.1 200 OK
Content-Type: application/json

{
    "a": {},
    "d": "E1aoCawdBMPw0TfHtuHgQvfu5AzAHWUadzv9CCtUhZlI", // adds digest
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
    "i":"did:keri:EmkPreYpZfFk66jpf3uFv7vklXKhzBrAqjsKAn2EDIPM",
    "s":"E46jrVPTzlSkUPqGGeIZ8a8FWS7a6s4reAXRZOkogZ2A",
    "a":{"dt":"2021-06-09T17:35:54.169967+00:00"},
    "p":[],
    "r":[],
    "d":"E5NscgYCVjzrCpmBu8ztQND8S_1h3XLtqh0c0vi9gxwo"
}
-0B+LsV0MWSqowHYQ+Hg5yvR6GIb6mPQ4orQ4tPRMNCcnEkYCtZELqicA216bucHOlP5m0dZorojkZY+tgLD3v6DA==


HTTP/1.1 200 OK
Content-Type: application/json

{
    "v":"ACDC10JSON00011c_",
    "i":"did:keri:EmkPreYpZfFk66jpf3uFv7vklXKhzBrAqjsKAn2EDIPM",
    "s":"E46jrVPTzlSkUPqGGeIZ8a8FWS7a6s4reAXRZOkogZ2A",
    "a":{"dt":"2021-06-09T17:35:54.169967+00:00"},
    "p":[],
    "r":[],
    "d":"E5NscgYCVjzrCpmBu8ztQND8S_1h3XLtqh0c0vi9gxwo"
}
```

### Listing attestations

```http
GET /attestations HTTP/1.1


HTTP/1.1 200 OK
Content-Type: application/json

[
    {
        "a": {},
        "d": "E1aoCawdBMPw0TfHtuHgQvfu5AzAHWUadzv9CCtUhZlI",
        "i": "issuer",
        "p": [],
        "r": [],
        "s": "E46jrVPTzlSkUPqGGeIZ8a8FWS7a6s4reAXRZOkogZ2A",
        "v": "ACDC10JSON00011c_"
    }
]
```