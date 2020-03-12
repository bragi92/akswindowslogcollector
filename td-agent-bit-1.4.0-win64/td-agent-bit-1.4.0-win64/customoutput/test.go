package main

import (
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"log"
	"crypto/rand"
	"crypto/sha256"

	"github.com/mastahyeti/certstore"
)

func main() {

	loganalyticsWorkspaceID := os.Getenv("CI_WSID1")
	logAnalyticsDomain := os.Getenv("CI_DOMAIN")

	if len(loganalyticsWorkspaceID) == 0 {
		log.Printf("Fuck")
	}	

	if len(logAnalyticsDomain) == 0 {
		log.Printf(logAnalyticsDomain)
		log.Printf("damn")
	}


	sig, err := signWithMyIdentity("Ben Toews", "hello, world!")
	if err != nil {
		log.Printf("%s \n", err.Error())
		//panic(err)
	}

	log.Printf("11111")
	fmt.Println(hex.EncodeToString(sig))
}


func signWithMyIdentity(cn, msg string) ([]byte, error) {
	// Open the certificate store for use. This must be Close()'ed once you're
	// finished with the store and any identities it contains.
	store, err := certstore.Open()
	log.Printf("22222")

	if err != nil {
		return nil, err
	}


	log.Printf("33333")


	defer store.Close()

	// Get an Identity slice, containing every identity in the store. Each of
	// these must be Close()'ed when you're done with them.
	idents, err := store.Identities()

	log.Printf("44444")

	if err != nil {
		return nil, err
	}

	// Iterate through the identities, looking for the one we want.
	var me certstore.Identity

	log.Printf("5555")

	for _, ident := range idents {
		defer ident.Close()

		crt, errr := ident.Certificate()


		if errr != nil {
			log.Fatal(errr)
		} else {


		//log.Printf(crt.Issuer.CommonName)

		if crt.Subject.CommonName == "5e0e87ea-67ac-4779-b6f7-30173b69112a" {
			me = ident
			log.Printf("We found the cert")
		}

	}


	}

	log.Printf("Certificate parsing done")

	if me == nil {
		return nil, errors.New("Couldn't find my identity")
	}

	// Get a crypto.Signer for the identity.
	signer, err := me.Signer()
	if err != nil {
		return nil, err
	}

	// Digest and sign our message.
	digest := sha256.Sum256([]byte(msg))
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}

	return signature, nil
}
