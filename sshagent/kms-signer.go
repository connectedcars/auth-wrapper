package sshagent

// TODO: Move to google kms package instead

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"

	cloudkms "cloud.google.com/go/kms/apiv1"
	"golang.org/x/crypto/ssh"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

// KMSSigner is an interface for an opaque private key that can be used for
// signing operations. For example, an RSA key kept in a hardware module.
type KMSSigner interface {
	crypto.Signer
	Digest() crypto.Hash
	SSHPublicKey() ssh.PublicKey
}

// kmsSigner is a key
type kmsSigner struct {
	ctx          context.Context
	client       *cloudkms.KeyManagementClient
	keyName      string
	publicKey    crypto.PublicKey
	sshPublicKey ssh.PublicKey
	digest       crypto.Hash
	forceDigest  bool
}

// CryptoHashLookup maps crypto.hash to string name
var CryptoHashLookup = map[crypto.Hash]string{
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

// NewKMSSigner creates a new instance
func NewKMSSigner(keyName string, forceDigest bool) (signer KMSSigner, err error) {
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

	sshPublicKey, err := ssh.NewPublicKey(abstractKey)
	if err != nil {
		return nil, fmt.Errorf("ssh.ParsePublicKey: %+v", err)
	}

	var publicKey crypto.PublicKey
	var digestType crypto.Hash
	switch abstractKey.(type) {
	case *rsa.PublicKey:
		publicKey = abstractKey.(*rsa.PublicKey)
		keySize := publicKey.(*rsa.PublicKey).Size() * 8
		switch keySize {
		case 2048:
			fallthrough
		case 3072:
			digestType = crypto.SHA256
		case 4096:
			digestType = crypto.SHA512
		default:
			return nil, fmt.Errorf("unsupported RSA key size %v", keySize)
		}

	case *ecdsa.PublicKey:
		publicKey = abstractKey.(*ecdsa.PublicKey)
		bitSize := publicKey.(*ecdsa.PublicKey).Curve.Params().BitSize
		switch bitSize {
		case 256:
			digestType = crypto.SHA256
		case 384:
			digestType = crypto.SHA384
		default:
			return nil, fmt.Errorf("unsupported ECDSA bit size %v", bitSize)
		}

	default:
		return nil, fmt.Errorf("key %q is not supported format", keyName)
	}

	return &kmsSigner{
		keyName:      keyName,
		ctx:          ctx,
		client:       client,
		publicKey:    publicKey,
		digest:       digestType,
		sshPublicKey: sshPublicKey,
		forceDigest:  forceDigest,
	}, nil
}

// Sign with key
func (kmss *kmsSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	// Check opts to see if the digest algo matches
	if !kmss.forceDigest && opts.HashFunc() != kmss.digest {
		return nil, fmt.Errorf("Requested hash: %v, supported hash %v", CryptoHashLookup[opts.HashFunc()], CryptoHashLookup[kmss.digest])
	}

	// Build the request.
	var digestPayload kmspb.Digest
	switch kmss.digest {
	case crypto.SHA256:
		digestPayload = kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest,
			},
		}
	case crypto.SHA384:
		digestPayload = kmspb.Digest{
			Digest: &kmspb.Digest_Sha384{
				Sha384: digest,
			},
		}
	case crypto.SHA512:
		digestPayload = kmspb.Digest{
			Digest: &kmspb.Digest_Sha512{
				Sha512: digest,
			},
		}
	}
	req := &kmspb.AsymmetricSignRequest{
		Name:   kmss.keyName,
		Digest: &digestPayload,
	}

	// Query the API.
	res, err := kmss.client.AsymmetricSign(kmss.ctx, req)
	if err != nil {
		return nil, fmt.Errorf("%v\nrequested hash: %v", err, CryptoHashLookup[opts.HashFunc()])
	}

	return res.Signature, nil
}

// Public fetches public key
func (kmss *kmsSigner) Public() crypto.PublicKey {
	return kmss.publicKey
}

// SSHPublicKey fetches public key in ssh format
func (kmss *kmsSigner) SSHPublicKey() ssh.PublicKey {
	return kmss.sshPublicKey
}

// Digest returns hash algo used for this key
func (kmss *kmsSigner) Digest() crypto.Hash {
	return kmss.digest
}
