#!/bin/bash

set -ev
# https://legacy.thomas-leister.de/eine-eigene-openssl-ca-erstellen-und-zertifikate-ausstellen/

## NOTE: Rusttls needs V3 
## Workaround: add "subjectAltName" to cert
# https://www.mail-archive.com/openssl-users@openssl.org/msg24211.html

# Create a new CA
openssl genpkey -algorithm ed25519 -out ca-key.pem
openssl req -x509 -new -key ca-key.pem -subj "/C=DE/CN=foobar-x-ca" -days 3651 -out ca.crt -sha512

# Create a server certificate
openssl genpkey -algorithm ed25519 -out server-key.pem
openssl req -new -key server-key.pem -subj "/C=DE/CN=server-foo" -out server.csr -sha512  -config san.cnf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca-key.pem -CAcreateserial -out server-cert.crt -days 3650 -sha512  -extensions v3_req -extfile san.cnf

# Create a client certificate
openssl genpkey -algorithm ed25519 -out client-key.pem
openssl req -new -key client-key.pem -subj "/C=DE/CN=client-foo" -out client.csr -sha512 -config san.cnf
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca-key.pem -CAcreateserial -out client-cert.crt -days 3650 -sha512 -extensions v3_req -extfile san.cnf


openssl x509 -in ca.crt  -text -noout
openssl x509 -in server-cert.crt  -text -noout
openssl x509 -in client-cert.crt  -text -noout

