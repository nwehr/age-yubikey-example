package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/ascii85"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"filippo.io/age"
	"github.com/go-piv/piv-go/piv"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	if len(os.Args) < 2 {
		return
	}

	if os.Args[1] == "-s" {
		if err := setup(); err != nil {
			fmt.Println(err)
		}

		return
	}

	keyFile, pubFile, err := keyFiles()
	if err != nil {
		fmt.Printf("could not open key files: %v\n", err)
		os.Exit(1)
	}

	defer keyFile.Close()
	defer pubFile.Close()

	messageFile, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Printf("could not open message file: %v\n", err)
		os.Exit(1)
	}

	defer messageFile.Close()

	yubikey, err := yubikey()
	if err != nil {
		fmt.Printf("could not open card: %v\n", err)
		os.Exit(1)
	}

	defer yubikey.Close()

	identity, err := protectedIdentity(keyFile, yubikey, piv.SlotCardAuthentication)
	if err != nil {
		fmt.Printf("could not get identity: %v\n", err)
		os.Exit(1)
	}

	decrypter, err := age.Decrypt(messageFile, identity)
	if err != nil {
		fmt.Printf("could not setup decrypter: %v\n", err)
		os.Exit(1)
	}

	io.Copy(os.Stdout, decrypter)
}

func protectedIdentity(r io.Reader, yubikey *piv.YubiKey, slot piv.Slot) (age.Identity, error) {
	decoded, err := ioutil.ReadAll(ascii85.NewDecoder(r))
	if err != nil {
		return nil, fmt.Errorf("could not read message file: %v", err)
	}

	cert, err := yubikey.Attest(slot)
	if err != nil {
		return nil, fmt.Errorf("could not get certificate: %v", err)
	}

	priv, err := yubikey.PrivateKey(slot, cert.PublicKey, piv.KeyAuth{PINPrompt: ttyPin, PINPolicy: piv.PINPolicyOnce})
	if err != nil {
		return nil, fmt.Errorf("could not setup private key: %v", err)
	}

	decrypter, ok := priv.(crypto.Decrypter)
	if !ok {
		return nil, fmt.Errorf("priv does not impliment Decrypter")
	}

	decrypted, err := decrypter.Decrypt(rand.Reader, decoded, nil)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt key file: %v", err)
	}

	identity, err := age.ParseX25519Identity(string(decrypted))
	if err != nil {
		return nil, fmt.Errorf("could not parse identity: %v", err)
	}

	return identity, nil
}

func keyFiles() (*os.File, *os.File, error) {
	keyFile, err := os.OpenFile(".key", os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, nil, fmt.Errorf("could not open file: %v", err)
	}

	pubFile, err := os.OpenFile(".key.pub", os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, nil, fmt.Errorf("could not open file: %v", err)
	}

	return keyFile, pubFile, nil
}

func yubikey() (*piv.YubiKey, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("could not list cards: %v", err)
	}

	if len(cards) == 0 {
		return nil, fmt.Errorf("no cards detected")
	}

	yubikey, err := piv.Open(cards[0])
	if err != nil {
		return nil, fmt.Errorf("could not open card %s: %v", cards[0], err)
	}

	return yubikey, nil
}

func setup() error {
	keyFile, pubFile, err := keyFiles()
	if err != nil {
		return fmt.Errorf("could not open key files: %v", err)
	}

	defer keyFile.Close()
	defer pubFile.Close()

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return fmt.Errorf("could not generate identity: %w", err)
	}

	yubikey, err := yubikey()
	if err != nil {
		return fmt.Errorf("could not get yubikey: %v", err)
	}

	cert, err := yubikey.Certificate(piv.SlotCardAuthentication)
	if err != nil {
		return fmt.Errorf("could not get certificate: %v", err)
	}

	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, cert.PublicKey.(*rsa.PublicKey), []byte(identity.String()))
	if err != nil {
		return fmt.Errorf("could not encrypt private key: %v", err)
	}

	encoder := ascii85.NewEncoder(keyFile)
	encoder.Write(encrypted)
	encoder.Close()

	io.WriteString(pubFile, identity.Recipient().String())

	return nil
}

func ttyPin() (string, error) {
	fmt.Print("pin: ")

	tty, err := os.Open("/dev/tty")
	if err != nil {
		return "", err
	}

	defer tty.Close()
	defer fmt.Println()

	pin, err := terminal.ReadPassword(int(tty.Fd()))

	return string(pin), err
}
