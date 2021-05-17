# TLS Key & Cert

Generate key and self signed certificate for testing. Valid for 100 years only.

`openssl req -x509 -newkey rsa:4096 -keyout tls.key -out tls.crt -days 36500 -nodes -subj "/C=HU/ST=Budapest/L=Budapest/O=My Organization Ltd./OU=Unit/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"`
