package main

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io/ioutil"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

func wordlistRead(language string) ([]string, error) {
	var data []byte
	switch language {
	case "english":
		data, _ = ioutil.ReadFile("wordlist/english.txt")
	case "korean":
		data, _ = ioutil.ReadFile("wordlist/korean.txt")
	}

	wordlist := strings.Split(strings.TrimSpace(string(data)), "\n")
	return wordlist, nil
}

// Generate random entropy
func generateEntropy(numBytes int) ([]byte, error) {
	entropy := make([]byte, numBytes)
	_, err := rand.Read(entropy)
	if err != nil {
		return nil, err
	}
	return entropy, nil
}

// Compute a checksum for the entropy
func calculateChecksum(entropy []byte) uint32 {
	hash := crc32.ChecksumIEEE(entropy)
	return hash >> (32 - len(entropy)*8/32)
}

// Convert a given entropy to BIP39 words
func entropyToWords(entropy []byte, wordlist []string) ([]string, error) {
	if len(entropy) < 4 {
		return nil, fmt.Errorf("entropy size should be at least 4 bytes")
	}
	words := make([]string, len(entropy)*8/32+1)
	for i := 0; i < len(entropy)*8/32; i++ {
		index := binary.BigEndian.Uint32(entropy[i*4:i*4+4]) % uint32(len(wordlist))
		words[i] = wordlist[index]
	}
	checksum := calculateChecksum(entropy)
	index := checksum % uint32(len(wordlist))
	words[len(words)-1] = wordlist[index]
	return words, nil
}

func GenerateMnemonicCode(language string, bitSize int) string {
	wordlist, _ := wordlistRead(language)
	entropy, _ := generateEntropy(bitSize)
	words, _ := entropyToWords(entropy, wordlist)

	return fmt.Sprint(strings.Join(words, " "))
}

func Seed(mnemonic string, password string) []byte {
	return pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"+password), 2048, 64, sha512.New)
}
