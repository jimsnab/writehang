#!/bin/bash

export SAN="DNS:localhost"

# Mint CA
openssl genrsa -out ca.key 2048
openssl req -new -key ca.key -x509 -days 3650 -out ca.crt -subj /C=US/ST=Wyoming/O="NAB"/CN="Localhost Root"

# Mint Server Cert
openssl genrsa -out server.key 2048
openssl req -new -nodes -key server.key -out server.csr -subj /C=US/ST=Wyoming/L=Cody/O="Localhost Server"/CN=localhost
openssl x509 -req -extfile <(printf "subjectAltName=$SAN") -days 9999 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt

# Mint Client Cert
openssl genrsa -out client.key 2048
openssl req -new -nodes -key client.key -out client.csr -subj /C=US/ST=Wyoming/L=Cody/O="Localhost Client 1"/CN=localhost
openssl x509 -req -extfile <(printf "subjectAltName=$SAN") -days 9999 -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt
