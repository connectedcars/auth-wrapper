package ssh

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type kmsKeyring struct {
	mu     sync.Mutex
	signer *KMSSigner

	locked     bool
	passphrase []byte
}

var errLocked = errors.New("agent: locked")

// NewKMSKeyring returns an Agent that holds keys in memory.  It is safe
// for concurrent use by multiple goroutines.
func NewKMSKeyring(signer *KMSSigner) agent.Agent {
	// TODO: Create keys and use signer key
	return &kmsKeyring{signer: signer}
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
	r.mu.Lock()
	defer r.mu.Unlock()

	var ids []*agent.Key

	pub := r.signer.PublicKey()
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
	r.mu.Lock()
	defer r.mu.Unlock()

	wanted := key.Marshal()

	if bytes.Equal(r.signer.PublicKey().Marshal(), wanted) {
		if flags == 0 {
			return r.signer.SignWithSSHAlgorithm(rand.Reader, data, ssh.SigAlgoRSASHA2512)
		} else {
			var algorithm string
			switch flags {
			case agent.SignatureFlagRsaSha256:
				algorithm = ssh.SigAlgoRSASHA2256
			case agent.SignatureFlagRsaSha512:
				algorithm = ssh.SigAlgoRSASHA2512
			default:
				return nil, fmt.Errorf("agent: unsupported signature flags: %d", flags)
			}
			return r.signer.SignWithSSHAlgorithm(rand.Reader, data, algorithm)

		}

	}
	return nil, errors.New("not found")
}
