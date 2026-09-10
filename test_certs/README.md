# TLS Key & Cert

## PKI Key-Pair

Generate key and self-signed certificate for testing. Valid for 100 years only.

`openssl req -x509 -newkey rsa:4096 -keyout tls.key -out tls.crt -days 36500 -nodes -set_serial 0x1000 -subj "/C=HU/ST=Budapest/L=Budapest/O=My Organization Ltd./OU=Unit/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"`

## Cert Revocation List

Generate a CRL valid for 100 years. Serial `1000` (the test cert) is revoked.

```sh
printf 'R\t360910122640Z\t260910122640Z\t1000\tunknown\t/CN=localhost\n' > index.txt
echo 01 > crlnumber
openssl ca -batch -gencrl -cert tls.crt -keyfile tls.key -crldays 36500 -out ca.crl -config <(printf '%s\n' '[ca]' 'default_ca=CA_default' '[CA_default]' 'database=index.txt' 'crlnumber=crlnumber' 'default_md=sha256')
rm crlnumber*
rm index.txt
```
