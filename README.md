# PeerCord
Audio and Video call application with user privacy insurance.

## Dependencies

- Go 1.21
- [portaudio](https://github.com/gordonklaus/portaudio/tree/master)
```shell
# On Mac with brew
brew install portaudio
# On Ubuntu
sudo apt-get install portaudio19-dev
```
- [camtron](https://github.com/vee2xx/camtron)
  - Does not require any specific installation steps. When the app is first run, it will automatically download the required binaries and placed them at the top-level directory, which may take some time.

## Run the app

Before running the peercord peer, you need to initialize bootstrap.go:
```shell
cd bootstrap
go run bootstrap.go
```
Run the app (one node) with the following command at the top-level directory.
```shell
go run peercord.go
```

## Run tests

The unit tests can be run using the following command. The recommended timeout is `5m`.
```shell
go test -timeout <timeout> -v -race -run <test name> ./peer/tests/unit

# run all unit tests with recommended timeout
go test -timeout 5m -v -race -run TestCrypto ./peer/tests/unit
go test -timeout 5m -v -race -run Test_DHT ./peer/tests/unit
go test -timeout 5m -v -race -run Test_EigenTrust ./peer/tests/unit
go test -timeout 5m -v -race -run Test_Multicast ./peer/tests/unit
go test -timeout 5m -v -race -run TestPeercord ./peer/tests/unit
```


The integration tests can be run using the following command. The recommended timeout is `20m`.
```shell
go test -timeout <timeout> -v -race -run <test name> ./peer/tests/integration

# run all integration tests with recommended timeout
go test -timeout 20m -v -race -run TestCrypto ./peer/tests/integration
go test -timeout 20m -v -race -run Test_Multicast ./peer/tests/integration
```

The key exchange latency measurements can be run with the following command. We recommend a timeout value of `60m`.
```shell
go test -timeout <timeout> -v -race -run ^TestCrypto_Perf_DH_<Key_Exchange|Removal|Addition>$ ./peer/tests/perf

# run all latency measurements with recommended timeout
go test -timeout 60m -v -race -run ^TestCrypto_Perf_DH_Key_Exchange$ ./peer/tests/measure
go test -timeout 60m -v -race -run ^TestCrypto_Perf_DH_Removal$ ./peer/tests/measure
go test -timeout 60m -v -race -run ^TestCrypto_Perf_DH_Addition$ ./peer/tests/measure
```
