# CERT

## Abstruct

Execute `cert/mk-tls.sh` to create `LSP_KEY` and `LSP_CERT`.

```bash
cd cert
vi mk-tls.sh
...(edit)...

./mk-tls.sh NayutaHub03
```

### note

Created cert is for `localhost`.  
If used on a client, it will need to be overwritten with "localhost".

```javascript
const client = new LspClient(
  address,
  credentials,
  {'grpc.ssl_target_name_override': 'localhost'}
)
```

```go
creds := credentials.NewTLS(&tls.Config{
	ServerName: "localhost",
	RootCAs:    x509.NewCertPool(),
})
option = grpc.WithTransportCredentials(creds)
client, err = grpc.Dial(address, option)
```

## usage

### mk-tls.sh

* Create CA key and cert if not exist "tls_ca_key".
* Create server key if not exist "DIRNAME/tls_lspd.key".
* Create server CERT if not exist "DIRNAME/tls_lspd.cert".

```bash
./mk-tls.sh <DIRNAME>
```

### read-tls.sh

```bash
./read-tls.sh <DIRNAME>
```

### update-lsp-cert.sh

Update only `<DIRNAME>/tls_lspd.cert` and output `LSP_CERT`.  
`LSP_CERT` is used to update lspd.env.

```bash
./update-lsp-cert.sh <DIRNAME>
```
