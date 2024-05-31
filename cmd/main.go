package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/rullyafrizal/kuncisurga"
	"log"
	"os"
	"time"
)

const (
	rawMode     = "raw"
	encodedMode = "encoded"
	pemMode     = "pem"
)

func main() {
	log.SetOutput(os.Stdout)

	var mode string
	flag.StringVar(&mode, "mode", "pem", " output mode (raw/encoded/pem)")
	flag.Parse()
	log.Printf("Starting the key pair generation with %v mode\n", mode)

	startTime := time.Now()

	gen := kuncisurga.NewGenerator()
	ctx := context.Background()

	switch mode {
	case rawMode:
		// Generate raw key pair
		rawKeyPair, err := gen.GenerateRawKeyPair(ctx)
		if err != nil {
			log.Fatalf("Error generating raw key pair: %v", err)
			return
		}
		fmt.Printf("Raw Private Key: %v\n", rawKeyPair.Private)
		fmt.Printf("Raw Public Key: %v\n", rawKeyPair.Public)
		log.Println("Raw key pair generated successfully")
	case encodedMode:
		// Generate encoded key pair
		encodedKeyPair, err := gen.GenerateEncodedKeyPair(ctx)
		if err != nil {
			log.Fatalf("Error generating encoded key pair: %v", err)
			return
		}
		fmt.Printf("Encoded Private Key: %v\n", encodedKeyPair.Private)
		fmt.Printf("Encoded Public Key: %v\n", encodedKeyPair.Public)
		log.Println("Encoded key pair generated successfully")
	default:
		// Generate PEM key pair
		pemKeyPair, err := gen.GeneratePEMKeyPair(ctx)
		if err != nil {
			log.Fatalf("Error generating PEM key pair: %v", err)
			return
		}
		fmt.Printf("PEM Private Key:\n%s", pemKeyPair.Private)
		fmt.Printf("PEM Public Key:\n%s", pemKeyPair.Public)
		log.Println("PEM key pair generated successfully")
	}

	elapsedTime := time.Since(startTime)
	log.Printf("Key pair generation completed in %v", elapsedTime)
}
