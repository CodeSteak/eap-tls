#!/bin/bash

# Convert PEM to DER
for f in *-cert.pem ca.pem
do
    openssl x509 -in $f -inform PEM -out "${f%.*}".der -outform DER
done

# Convert PKCS8Key to DER
for f in server-key.pem client-key.pem
do
    openssl pkcs8 -topk8 -nocrypt -in $f -inform PEM -out "${f%.*}".der -outform DER
done
