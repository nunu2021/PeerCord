# PeerCord
Audio and Video call application with user privacy insurance.

## Dependencies

go version 1.21
[portaudio][https://github.com/gordonklaus/portaudio/tree/master]
[camtron][https://github.com/vee2xx/camtron]

## Run the app
One can run the app executing the command `go run peercord.go` when in the top level directory of the repository

## Run tests

The unit tests can be run using `go test -timeout {timeout value} -v -race -run ^{test name}$ go.dedis.ch/cs438/peer/unit` (recommended timeout: 5m)
The integration tests can be run using `go test -timeout {timeout value} -v -race -run ^{test name}$ go.dedis.ch/cs438/peer/integration` (recommended timeout: 20m)
For the cryptography part, the Key exchange latency measurements can be run using `go test -timeout {timeout value} -v -race -run ^TestCrypto_Perf_DH_{Key_Exchange/Removal/Addition}$ go.dedis.ch/cs438/peer/impl` (recommended timeout: 60m)