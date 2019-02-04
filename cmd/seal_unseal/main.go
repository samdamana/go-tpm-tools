package main

import (
	"encoding/hex"
	"flag"
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

var (
	secretMessage = "SamIsMySpecialGuy"
	tpmPath       = flag.String("tpm-path", "/dev/tpm0", "path to a TPM character device or socket")
	pcr           = flag.Int("pcr", 7, "PCR to seal data to. Must be within [0, 23].")
	srkHandle     = tpm2.HandleNull // TODO
	srkPassword   = ""              // TODO
	srkTemplate   = tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagDecrypt | tpm2.FlagNoDA,
		AuthPolicy: nil,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:    2048,
			Exponent:   0,
			ModulusRaw: make([]byte, 256),
		},
	}
)

func main() {
	fmt.Println("Testing Seal/Unseal vTPM stuff.")
	fmt.Printf("Secret Str: \"%s\"\nSecret Hex: %s\n", secretMessage, hex.EncodeToString([]byte(secretMessage)))

}
