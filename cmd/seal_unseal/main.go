package main

import (
	"bytes"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var (
	secretMessage = "SamIsMySpecialGuy"
	tpmPath       = flag.String("tpm-path", "/dev/tpm0", "path to a TPM character device or socket")
	pcr           = flag.Int("pcr", 7, "PCR to seal data to. Must be within [0, 23].")
	password      = flag.String("password", "", "password to seal the data with")
	filename      = flag.String("filename", "key1.pem", "key file to save and or load.")
	seal          = flag.Bool("seal", true, "Whether to seal.")
	unseal        = flag.Bool("unseal", true, "Whether to unseal.")
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
	if *seal {
		err := sealSecret(*pcr, *tpmPath, *password, *filename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}

	if *unseal {
		err := unsealSecret(*pcr, *tpmPath, *password, *filename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}
}

func sealSecret(pcr int, tpmPath, password, filename string) (retErr error) {
	fmt.Println("***** SEAL SECRET *****")
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

	// pcrVal, err := tpm2.ReadPCR(rwc, pcr, tpm2.AlgSHA256)
	// if err != nil {
	// 	return fmt.Errorf("unable to read PCR: %v", err)
	// }
	// fmt.Printf("PCR %v value: 0x%x\n", pcr, pcrVal)

	sessHandle, policy, err := policyPCRPasswordSession(rwc, pcr, password)
	if err != nil {
		return fmt.Errorf("unable to get policy: %v", err)
	}
	defer func() {
		if err := tpm2.FlushContext(rwc, sessHandle); err != nil {
			retErr = fmt.Errorf("%v\nunable to flush session: %v", retErr, err)
		}
	}()
	fmt.Printf("Session Handle: 0x%x\nPolicy: %v\n", sessHandle, policy)

	fmt.Println("Data to be sealed...")
	dataToSeal := []byte(secretMessage)
	fmt.Printf("Secret Str: \"%s\"\nSecret Hex: %s\n", secretMessage, hex.EncodeToString(dataToSeal))
	privateArea, publicArea, err := tpm2.Seal(rwc, srkHandle, srkPassword, password, policy, dataToSeal)
	if err != nil {
		return fmt.Errorf("unable to seal data: %v", err)
	}

	enc, err := pemEncode(privateArea, publicArea)
	if err != nil {
		return err
	}

	if err = ioutil.WriteFile(filename, enc, 0644); err != nil {
		return err
	}
	return nil
}

func unsealSecret(pcr int, tpmPath, password, filename string) (retErr error) {
	fmt.Println("***** UNSEAL SECRET *****")
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

	keyData, err := ioutil.ReadFile(filename)
	privateArea, publicArea, err := pemDecode(keyData)
	if err != nil {
		return err
	}

	// Load the sealed data into the TPM.
	objectHandle, _, err := tpm2.Load(rwc, srkHandle, srkPassword, publicArea, privateArea)
	if err != nil {
		return fmt.Errorf("unable to load data: %v", err)
	}
	defer func() {
		if err := tpm2.FlushContext(rwc, objectHandle); err != nil {
			retErr = fmt.Errorf("%v\nunable to flush object handle %q: %v", retErr, objectHandle, err)
		}
	}()

	fmt.Printf("Loaded secrets objectHandle: 0x%x\n", objectHandle)
	// Create the authorization session
	sessHandle, _, err := policyPCRPasswordSession(rwc, pcr, password)
	if err != nil {
		return fmt.Errorf("unable to get auth session: %v", err)
	}
	defer func() {
		if err := tpm2.FlushContext(rwc, sessHandle); err != nil {
			retErr = fmt.Errorf("%v\nunable to flush session: %v", retErr, err)
		}
	}()

	// Unseal the data
	unsealedData, err := tpm2.UnsealWithSession(rwc, sessHandle, objectHandle, password)
	if err != nil {
		return fmt.Errorf("unable to unseal data: %v", err)
	}
	fmt.Printf("Unsealed: %s\n", string(unsealedData))
	return nil
}

func pemEncode(private, public []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{
		Type:  "SEALED PRIVATE",
		Bytes: private,
	}); err != nil {
		return nil, err
	}
	if err := pem.Encode(buf, &pem.Block{
		Type:  "SEALED PUBLIC",
		Bytes: public,
	}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func pemDecode(enc []byte) ([]byte, []byte, error) {
	privateBlock, rest := pem.Decode(enc)
	if privateBlock == nil || privateBlock.Type != "SEALED PRIVATE" {
		return nil, nil, fmt.Errorf("Error decoding PEM block. Does not contain SEALED PRIVATE: %s", enc)
	}
	publicBlock, _ := pem.Decode(rest)
	if publicBlock == nil || publicBlock.Type != "SEALED PUBLIC" {
		return nil, nil, fmt.Errorf("Error decoding PEM block. Does not contain SEALED PUBLIC: %s", rest)
	}
	return privateBlock.Bytes, publicBlock.Bytes, nil
}

func policyPCRPasswordSession(rwc io.ReadWriteCloser, pcr int, password string) (sessHandle tpmutil.Handle, policy []byte, retErr error) {
	// This is not a very secure session but since this TPM access is single-op
	// and local it is not a big deal.
	sessHandle, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,  /*tpmKey*/
		tpm2.HandleNull,  /*bindKey*/
		make([]byte, 16), /*nonceCaller*/
		nil,              /*secret*/
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return tpm2.HandleNull, nil, fmt.Errorf("unable to start session: %v", err)
	}
	defer func() {
		if sessHandle != tpm2.HandleNull && err != nil {
			if err := tpm2.FlushContext(rwc, sessHandle); err != nil {
				retErr = fmt.Errorf("%v\nunable to flush session: %v", retErr, err)
			}
		}
	}()

	pcrSelection := tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: []int{pcr},
	}

	// An empty expected digest means that digest verification is skipped.
	if err := tpm2.PolicyPCR(rwc, sessHandle, nil /*expectedDigest*/, pcrSelection); err != nil {
		return sessHandle, nil, fmt.Errorf("unable to bind PCRs to auth policy: %v", err)
	}

	if err := tpm2.PolicyPassword(rwc, sessHandle); err != nil {
		return sessHandle, nil, fmt.Errorf("unable to require password for auth policy: %v", err)
	}

	policy, err = tpm2.PolicyGetDigest(rwc, sessHandle)
	if err != nil {
		return sessHandle, nil, fmt.Errorf("unable to get policy digest: %v", err)
	}
	return sessHandle, policy, nil
}
