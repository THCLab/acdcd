# Tda-deamon

## API

### Creating attestation

Creates a new attestation signed with current priv key.
The issuer field (`i`) is ignored and the current user ID is used automatically instead.

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

Parses the attestation and returns its JSON without the signature.

Returns `403 forbidden` if the signature can't be verified.

### Listing attestations

```http
GET /attestations HTTP/1.1
```

## Notes about interactions between tda-deamon, [witness](https://github.com/THCLab/keri-witness-http) and [resolver](https://github.com/THCLab/keri-resolver)

### Run

1. Start the resolver. You can set the listening port with `--api-port` flag, the default is 9599.

2. Start witnesses. It will create the default database file `witness_db` and will use default port 3030. If you want to use more than one witness, each witness should have a separate database and port. It can be set with console arguments. When you start the witness, it will show you its identifier.
**Note**: If you changed the resolver listening port in the previous step, you should set it for all of your witnesses using `-r` flag.

3. Start tda. You can set witnesses used by tda using config file, their identifiers can be taken from the previous step. You can also set a witness threshold, default there are no witnesses and the threshold is 0.
Tda will generate its inception event and will send it to the designated witnesses. When witnesses collect enough receipts, they will publish the controller's current key config in the resolver.
