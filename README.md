# IVYLauncher Signer

Sign msg by signer to appoint a address to participate the Validator Round of IVYLauncher

# Download the Executables

you can download the executables by click [here](https://github.com/ivyido/validator-signer/releases/tag/v1.0.0)

# Build the source

## Requirements

- [Go](https://golang.org/doc/install) version 1.8 or higher, with `$GOPATH` set to your preferred directory

## Installation

- Ensure Go with the supported version is installed properly:

```bash
$ go version
$ go env GOROOT GOPATH
```

- Get the source code

```bash
git clone https://github.com/ivyido/validator-signer.git 
```

- Build the source

```bash
cd validator-signer 
go build -o signer .
```

# Sign

```bash
export PRIVATE_KEY={YOUR_PRIVATE_KEY} 
signer {YOUR_VALIDATOR_AGENT_ADDR} {MSG} 
```
