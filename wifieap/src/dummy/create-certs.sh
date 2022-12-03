set -ev
# https://legacy.thomas-leister.de/eine-eigene-openssl-ca-erstellen-und-zertifikate-ausstellen/

# Note: CA password is "123456"

# create dh param
test -f dh.pem || openssl dhparam -out dh.pem 2048

# Create a new CA
openssl genrsa -aes256 -out ca-key.pem 2048
openssl req -x509 -new -nodes -extensions v3_ca -key ca-key.pem -days 36500 -out ca.pem -sha512

# Create a server certificate
openssl genrsa -out server-key.pem 2048
openssl req -new -key server-key.pem -out server.csr -sha512
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -days 36500 -sha512

# Create a client certificate
openssl genrsa -out client-key.pem 2048
openssl req -new -key client-key.pem -out client.csr -sha512
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out client-cert.pem -days 36500 -sha512


