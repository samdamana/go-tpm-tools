package main

import (
	"bytes"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var (
	secretMessage = "SamIsMySpecialGuy"
	tpmPath       = flag.String("tpm-path", "/dev/tpm0", "path to a TPM character device or socket")
	pcr           = flag.Int("pcr", 7, "PCR to seal data to. Must be within [0, 23].")
	password      = flag.String("password", "", "password to seal the data with")
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

	fmt.Printf("SRK Handle: 0x%x\nSRK publicKey: %v\n", srkHandle, publicKey)

	pcrVal, err := tpm2.ReadPCR(rwc, pcr, tpm2.AlgSHA256)
	if err != nil {
		return fmt.Errorf("unable to read PCR: %v", err)
	}
	fmt.Printf("PCR %v value: 0x%x\n", pcr, pcrVal)

	sessHandle, policy, err := policyPCRPasswordSession(rwc, pcr, *password)
	if err != nil {
		return fmt.Errorf("unable to get policy: %v", err)
	}
	fmt.Printf("Session Handle: 0x%x\nPolicy: %v\n", sessHandle, policy)

	fmt.Println("Data to be sealed...")
	dataToSeal := []byte(secretMessage)
	fmt.Printf("Secret Str: \"%s\"\nSecret Hex: %s\n", secretMessage, hex.EncodeToString(dataToSeal))
	privateArea, publicArea, err := tpm2.Seal(rwc, srkHandle, srkPassword, *password, policy, dataToSeal)
	if err != nil {
		return fmt.Errorf("unable to seal data: %v", err)
	}

	enc, err := pemEncode(publicArea, privateArea)
	if err != nil {
		return err
	}
	fmt.Println(enc)

	// DONE
	return nil
}

func pemEncode(public, private []byte) (string, error) {
	buf := new(bytes.Buffer)
	publicBlock := &pem.Block{
		Type:  "SEALED PUBLIC",
		Bytes: public,
	}
	privateBlock := &pem.Block{
		Type:  "SEALED PRIVATE",
		Bytes: private,
	}
	if err := pem.Encode(buf, publicBlock); err != nil {
		return "", err
	}
	if err := pem.Encode(buf, privateBlock); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func policyPCRPasswordSession(rwc io.ReadWriteCloser, pcr int, password string) (sessHandle tpmutil.Handle, policy []byte, retErr error) {
	return tpm2.HandlePasswordSession, nil, nil
}
