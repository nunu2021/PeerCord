# PeerCord
Audio and Video call application with user privacy insurance.

## Dependencies

- go version 1.21
- [portaudio](https://github.com/gordonklaus/portaudio/tree/master)
```shell
# On MacOs with brew
brew install portaudio
# On Ubuntu
sudo apt-get install portaudio19-dev
```
[camtron](https://github.com/vee2xx/camtron)
- Does not require any specific installation steps. When the app is first run, it will automatically download the required binaries and placed them at the top-level directory, which may take some time.

## Run the app
One can run the app executing the command `go run peercord.go` when in the top level directory of the repository

## Run tests

The unit tests can be run using `go test -timeout {timeout value} -v -race -run ^{test name}$ go.dedis.ch/cs438/peer/unit` (recommended timeout: 5m)
The integration tests can be run using `go test -timeout {timeout value} -v -race -run ^{test name}$ go.dedis.ch/cs438/peer/integration` (recommended timeout: 20m)
For the cryptography part, the Key exchange latency measurements can be run using `go test -timeout {timeout value} -v -race -run ^TestCrypto_Perf_DH_{Key_Exchange/Removal/Addition}$ go.dedis.ch/cs438/peer/impl` (recommended timeout: 60m)