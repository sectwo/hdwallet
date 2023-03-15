package main

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func bip32KeyToECDSA(key Key) (*ecdsa.PrivateKey, error) {
	// convert the bip32 private key to an ECDSA private key
	//curve := elliptic.P256() // or crypto.S256() for secp256k1
	curve := crypto.S256()
	privateKey := new(ecdsa.PrivateKey)
	privateKey.PublicKey.Curve = curve
	privateKey.D = new(big.Int).SetBytes(key.Key)
	privateKey.D.Mod(privateKey.D, crypto.S256().Params().N)
	privateKey.PublicKey.X, privateKey.PublicKey.Y = curve.ScalarBaseMult(key.Key)
	return privateKey, nil
}

func GenerateAddressETH(pubKey ecdsa.PublicKey) common.Address {
	address := crypto.PubkeyToAddress(pubKey)

	return address
}
