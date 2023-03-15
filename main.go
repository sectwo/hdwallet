package main

import (
	"fmt"
)

func main() {
	// 1. BIP39 Process :
	// 1-1. Generate mnemonic code
	// 1-2. Generate master seed
	language := "korean"
	pwd := "abcd1234!@"
	byteSize := 32 // 256bit
	mnemonicCode := GenerateMnemonicCode(language, byteSize)
	fmt.Println("mnemonicCode : ", mnemonicCode)

	//masterSeed := Seed(mnemonicCode, pwd)
	masterSeed := Seed(mnemonicCode, pwd)
	fmt.Println("masterSeed : ", masterSeed)

	// 2. BIP32 Process
	// 2-1. Generate Master key
	masterKey, _ := NewMasterKey(masterSeed)
	fmt.Println("masterKey : ", masterKey)

	// 3. Calculating Dreiven path index(uint32) and generate derive childkey form path
	// example => ethPath = "m/44'/60'/0'/0/0"
	ethPath := "m/44'/60'/0'/0/0"
	childKey, err := DeriveKeyFromPath(masterKey, ethPath)
	if err != nil {
		fmt.Println("error : ", err)
	}

	fmt.Println("private key : ", childKey)
	fmt.Println("public key : ", childKey.PublicKey())

	// 4. From BIP32 Key to ECDSA(spec256k1)
	privKey, _ := bip32KeyToECDSA(*childKey)
	pubKey := privKey.PublicKey

	// 5. Generate Etherieum address
	addressETH := GenerateAddressETH(pubKey)

	fmt.Println("ETH Address : ", addressETH)

}
