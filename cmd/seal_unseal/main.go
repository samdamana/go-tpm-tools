package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm2"
)

var (
	secretMessage = "SamIsMySpecialGuy"
	tpmPath       = flag.String("tpm-path", "/dev/tpm0", "path to a TPM character device or socket")
	pcr           = flag.Int("pcr", 7, "PCR to seal data to. Must be within [0, 23].")
	srkPassword   = "" // TODO
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
	flag.Parse()

	if *pcr < 0 || *pcr > 23 {
		fmt.Fprintf(os.Stderr, "Invalid flag 'pcr': value %d is out of range", *pcr)
		os.Exit(1)
	}

	err := run(*pcr, *tpmPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(pcr int, tpmPath string) (retErr error) {
	fmt.Println("Testing Seal/Unseal vTPM stuff.")
	fmt.Printf("Secret Str: \"%s\"\nSecret Hex: %s\n", secretMessage, hex.EncodeToString([]byte(secretMessage)))
	// Open the TPM
	rwc, err := tpm2.OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("can't open TPM %q: %v", tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			retErr = fmt.Errorf("%v\ncan't close TPM %q: %v", retErr, tpmPath, err)
		}
	}()

	srkHandle, publicKey, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, "", srkPassword, srkTemplate)
	if err != nil {
		return fmt.Errorf("can't create primary key: %v", err)
	}
	defer func() {
		if err := tpm2.FlushContext(rwc, srkHandle); err != nil {
			retErr = fmt.Errorf("%v\nunable to flush SRK handle %q: %v", retErr, srkHandle, err)
		}
	}()

	fmt.Printf("srkHandle: 0x%x\npublicKey: %v\n", srkHandle, publicKey)

	return nil
}
