package ssh

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"

	cloudkms "cloud.google.com/go/kms/apiv1"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

// KMSSigner is a key
type KMSSigner struct {
	ctx       context.Context
	client    *cloudkms.KeyManagementClient
	keyName   string
	publicKey crypto.PublicKey
}

// Sign with key
func (kmss *KMSSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	// Build the request.
	// TODO: Check opts to see if the digest algo matches
	req := &kmspb.AsymmetricSignRequest{
		Name: kmss.keyName,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha512{
				Sha512: digest,
			},
		},
	}

	// Query the API.
	res, err := kmss.client.AsymmetricSign(kmss.ctx, req)
	if err != nil {
		return nil, err
	}

	return res.Signature, nil
}

// Public fetches public key
func (kmss *KMSSigner) Public() crypto.PublicKey {
	return kmss.publicKey
}

// NewKMSSigner creates a new instance
func NewKMSSigner(keyName string) (signer crypto.Signer, err error) {
	// Create the KMS client.
	ctx := context.Background()
	client, err := cloudkms.NewKeyManagementClient(ctx)
	if err != nil {
		log.Fatal(err)
	}

	// Retrieve the public key from KMS.
	response, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: keyName})
	if err != nil {
		return nil, fmt.Errorf("GetPublicKey: %v", err)
	}
	// Parse the key.
	block, _ := pem.Decode([]byte(response.Pem))
	abstractKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("x509.ParsePKIXPublicKey: %+v", err)
	}
	rsaKey, ok := abstractKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key %q is not RSA", keyName)
	}

	return &KMSSigner{keyName: keyName, ctx: ctx, client: client, publicKey: rsaKey}, nil
}
