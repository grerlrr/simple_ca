# Simple CA

This small command line utility creates CA certificates locally, and sign new server certificates.

## Create CA

Run the following command to create the root and intermediate certificates.

```shell
simple-ca ca -v
```

The generated private keys and certificates can be found at `~/.simple_ca`. You can then add the root and intermediate CA certificates to the OS' certificate storage.

## Create Server Certificate

Run the following command to create a wildcard certificate for `*.example.com`. You'll also need to provide SubjectAltName.

```shell
simple-ca server '*.example.com' '*.example.com' -v
```
