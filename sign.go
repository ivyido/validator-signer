package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/sha3"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func strip0x(s string) string {
	if strings.HasPrefix(s, "0x") {
		s = s[2:]
	}
	return s
}

func Sign(hash []byte, privateKey string) (string, error) {
	var key *ecdsa.PrivateKey
	var byteArr []byte

	if b, err := hex.DecodeString(strip0x(privateKey)); err != nil {
		return "", err
	} else {
		byteArr = b
	}
	if pk, err := crypto.ToECDSA(byteArr); err != nil {
		return "", err
	} else {
		key = pk
	}
	if sig, err := crypto.Sign(hash, key); err != nil {
		return "", err
	} else {
		// link https://eips.ethereum.org/EIPS/eip-155
		sig[64] = uint8(int(sig[64])) + 27
		return "0x" + hex.EncodeToString(sig), nil
	}
}

func SignHash(message []byte, privateKey string) (string, error) {
	msglen := []byte(strconv.Itoa(len(message)))
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte{0x19})
	hash.Write([]byte("Ethereum Signed Message:"))
	hash.Write([]byte{0x0A})
	hash.Write(msglen)
	hash.Write(message)
	buf := hash.Sum([]byte{})

	return Sign(buf, privateKey)
}

func SignValidator(validatorAgent, msg, privateKey string) (string, error) {
	addressType, _ := abi.NewType("address", "", nil)
	stringType, _ := abi.NewType("string", "", nil)
	arguments := abi.Arguments{
		{
			Type: addressType,
		},
		{
			Type: stringType,
		},
	}

	// abi encode
	bytes, err := arguments.Pack(
		common.HexToAddress(validatorAgent),
		msg,
	)

	if err != nil {
		return "", err
	}

	return SignHash(bytes, privateKey)
}

func loadPrivateKey() (privateKey string) {
	args := os.Args[1:]
	if len(args) > 3 {
		privateKey = args[2]
	}

	envPrivateKey := os.Getenv("PRIVATE_KEY")
	if len(envPrivateKey) > 0 {
		privateKey = envPrivateKey
	}

	if len(privateKey) == 0 {
		panic("must need privateKey")
	}

	return
}

func main() {
	// remove executable name from arguments
	args := os.Args[1:]
	validatorAgentAddr := args[0]
	msg := args[1]

	privateKey := loadPrivateKey()

	if result, err := SignValidator(validatorAgentAddr, msg, privateKey); err != nil {
		panic(err)
	} else {
		if _, err := fmt.Fprintf(os.Stdout, "%v\n", result); err != nil {
			panic(err)
		}
	}
}
