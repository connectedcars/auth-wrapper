package sshagent

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type kmsKeyring struct {
	signer KMSSigner

	locked     bool
	passphrase []byte
}

var errLocked = errors.New("agent: locked")

// NewKMSKeyring returns an Agent that holds keys in memory.  It is safe
// for concurrent use by multiple goroutines.
func NewKMSKeyring(kmsKeyPath string) (sshAgent agent.ExtendedAgent, err error) {
	privateKey, err := NewKMSSigner(kmsKeyPath, false)
	if err != nil {
		return nil, err
	}
	return &kmsKeyring{signer: privateKey}, nil
}

func (r *kmsKeyring) RemoveAll() error {
	return fmt.Errorf("removing keys not allowed")
}

func (r *kmsKeyring) Remove(_ ssh.PublicKey) error {
	return fmt.Errorf("removing keys not allowed")
}

func (r *kmsKeyring) Lock(_ []byte) error {
	return fmt.Errorf("locking agent not allowed")
}

func (r *kmsKeyring) Unlock(_ []byte) error {
	return fmt.Errorf("unlocking agent not allowed")
}

func (r *kmsKeyring) Add(_ agent.AddedKey) error {
	return fmt.Errorf("adding new keys not allowed")
}

// Signers returns signers for all the known keys.
func (r *kmsKeyring) Signers() ([]ssh.Signer, error) {
	return nil, fmt.Errorf("Signers not allowed")
}

// The keyring does not support any extensions
func (r *kmsKeyring) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

// List returns the identities known to the agent.
func (r *kmsKeyring) List() ([]*agent.Key, error) {
	var ids []*agent.Key

	pub := r.signer.SSHPublicKey()
	ids = append(ids, &agent.Key{
		Format:  pub.Type(),
		Blob:    pub.Marshal(),
		Comment: "my kms key"})

	return ids, nil
}

// Sign returns a signature for the data.
func (r *kmsKeyring) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return r.SignWithFlags(key, data, 0)
}

func (r *kmsKeyring) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	wanted := key.Marshal()

	if bytes.Equal(r.signer.SSHPublicKey().Marshal(), wanted) {
		// Ignore flags as they google key only supports one type of hashing.

		// Generate digest
		var digest []byte
		h := r.signer.Digest().New()
		h.Write(data)
		digest = h.Sum(nil)

		// Sign the digest
		signature, err := r.signer.Sign(rand.Reader, digest, r.signer.Digest())
		if err != nil {
			return nil, err
		}

		var algorithm string
		switch r.signer.Public().(type) {
		case *dsa.PublicKey:
			algorithm = ssh.KeyAlgoDSA // Not support by KMS
		case *rsa.PublicKey:
			switch r.signer.Digest() {
			case crypto.SHA1: // Not support by KMS
				algorithm = ssh.SigAlgoRSA
			case crypto.SHA256:
				algorithm = ssh.SigAlgoRSASHA2256
			case crypto.SHA512:
				algorithm = ssh.SigAlgoRSASHA2512
			default:
				return nil, fmt.Errorf("Unknown digest type %v", CryptoHashLookup[r.signer.Digest()])
			}
		case *ecdsa.PublicKey:
			switch r.signer.Digest() {
			case crypto.SHA256:
				algorithm = ssh.KeyAlgoECDSA256
			case crypto.SHA384:
				algorithm = ssh.KeyAlgoECDSA384
			case crypto.SHA512:
				algorithm = ssh.KeyAlgoECDSA521
			default:
				return nil, fmt.Errorf("Unknown digest type %v", CryptoHashLookup[r.signer.Digest()])
			}
		case *ed25519.PublicKey:
			algorithm = ssh.KeyAlgoED25519
		}

		return &ssh.Signature{
			Format: algorithm,
			Blob:   signature,
		}, nil
	}

	return nil, errors.New("not found")
}
