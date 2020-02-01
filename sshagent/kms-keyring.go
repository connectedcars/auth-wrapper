package sshagent

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type kmsKeyring struct {
	userPrivateKeyPath string
	caPrivateKeyPath   string
	userSigner         KMSSigner
	userSSHSigner      ssh.Signer
	caSigner           KMSSigner
	caSSHSigner        ssh.Signer

	locked     bool
	passphrase []byte
}

var errLocked = errors.New("agent: locked")

// NewKMSKeyring returns an Agent that holds keys in memory.  It is safe
// for concurrent use by multiple goroutines.
func NewKMSKeyring(userPrivateKeyPath string, caPrivateKeyPath string) (sshAgent agent.ExtendedAgent, err error) {
	userPrivateKey, err := NewKMSSigner(userPrivateKeyPath, false)
	if err != nil {
		return nil, err
	}
	userSSHSigner, err := NewSSHSignerFromKMSSigner(userPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed NewSignerFromSigner from: %v", err)
	}

	caPrivateKey, err := NewKMSSigner(caPrivateKeyPath, false)
	if err != nil {
		return nil, err
	}
	caSSHSigner, err := NewSSHSignerFromKMSSigner(caPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed NewSignerFromSigner from: %v", err)
	}

	return &kmsKeyring{
		userPrivateKeyPath: userPrivateKeyPath,
		caPrivateKeyPath:   caPrivateKeyPath,
		userSigner:         userPrivateKey,
		caSigner:           caPrivateKey,
		userSSHSigner:      userSSHSigner,
		caSSHSigner:        caSSHSigner,
	}, nil
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

// SSHCertificate adds support for modern hash type
type SSHCertificate struct {
	ssh.Certificate
}

// Type returns the key name. It is part of the PublicKey interface.
func (c *SSHCertificate) Type() string {
	return "rsa-sha2-512-cert-v01@openssh.com"
}

// List returns the identities known to the agent.
func (r *kmsKeyring) List() ([]*agent.Key, error) {
	var ids []*agent.Key

	userPublicKey := r.userSigner.SSHPublicKey()
	ids = append(ids, &agent.Key{
		Format:  userPublicKey.Type(),
		Blob:    userPublicKey.Marshal(),
		Comment: "user " + r.userPrivateKeyPath})

	// Add the CA public key so it's easy to copy paste
	caPublicKey := r.caSigner.SSHPublicKey()
	ids = append(ids, &agent.Key{
		Format:  caPublicKey.Type(),
		Blob:    caPublicKey.Marshal(),
		Comment: "ca " + r.caPrivateKeyPath})

	// Sign and add a user certificate to the keyring
	userCert := &SSHCertificate{ssh.Certificate{
		Key:             userPublicKey,
		KeyId:           "test",
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{"tlb"},
		ValidAfter:      0,
		ValidBefore:     ssh.CertTimeInfinity, // uint64(time.Now().Add(time.Minute * 60).Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions:      map[string]string{},
		},
	}}
	err := userCert.SignCert(rand.Reader, r.caSSHSigner)
	if err != nil {
		return nil, fmt.Errorf("failed SignCert from %v", err)
	}

	// TODO: the go lang ssh cert implementation does not support forcing rsa-sha2-256-cert-v01@openssh.com or rsa-sha2-512-cert-v01@openssh.com
	// To fix this we would need to replace the keyname in the certBlob with one of the names listed.
	certBlob := userCert.Marshal()
	ids = append(ids, &agent.Key{
		Format:  userCert.Type(),
		Blob:    certBlob,
		Comment: "user cert " + r.userPrivateKeyPath})

	return ids, nil
}

// Sign returns a signature for the data.
func (r *kmsKeyring) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return r.SignWithFlags(key, data, 0)
}

func (r *kmsKeyring) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	wanted := key.Marshal()

	if bytes.Equal(r.userSigner.SSHPublicKey().Marshal(), wanted) {
		// Ignore flags as they google key only supports one type of hashing.
		signature, err := r.userSSHSigner.Sign(rand.Reader, data)
		if err != nil {
			return nil, err
		}
		return signature, nil
	}

	return nil, errors.New("not found")
}
