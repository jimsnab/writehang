package main

import _ "embed"

//go:embed test_assets/ca.crt
var testRootCaPem []byte

//go:embed test_assets/client.crt
var testClientCertPem []byte

//go:embed test_assets/client.key
var testClientKeyPem []byte

//go:embed test_assets/server.crt
var testServerCertPem []byte

//go:embed test_assets/server.key
var testServerKeyPem []byte
