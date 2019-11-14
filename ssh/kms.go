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

var hashLookup = map[crypto.Hash]string{
	crypto.MD4:         "MD4",
	crypto.SHA1:        "SHA1",
	crypto.SHA224:      "SHA224",
	crypto.SHA256:      "SHA256",
	crypto.SHA384:      "SHA384",
	crypto.SHA512:      "SHA512",
	crypto.MD5SHA1:     "MD5SHA1",
	crypto.RIPEMD160:   "RIPEMD160",
	crypto.SHA3_224:    "SHA3_224",
	crypto.SHA3_256:    "SHA3_256",
	crypto.SHA3_384:    "SHA3_384",
	crypto.SHA3_512:    "SHA3_512",
	crypto.SHA512_224:  "SHA512_224",
	crypto.SHA512_256:  "SHA512_256",
	crypto.BLAKE2s_256: "BLAKE2s_256",
	crypto.BLAKE2b_256: "BLAKE2b_256",
	crypto.BLAKE2b_384: "BLAKE2b_384",
	crypto.BLAKE2b_512: "BLAKE2b_512",
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
		return nil, fmt.Errorf("%v\nhash: %v", err, hashLookup[opts.HashFunc()])
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
