package sshagent

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// SSHAlgorithmSigner and a comment
type SSHAlgorithmSigner struct {
	Signer  ssh.AlgorithmSigner
	Comment string
}

// SSHCertificate and a comment
type SSHCertificate struct {
	Certificate *ssh.Certificate
	Comment     string
}

type sshAlgorithmSignerKeyring struct {
	sshAlgorithmSigners []SSHAlgorithmSigner
	sshCertificates     []SSHCertificate
}

// NewSSHAlgorithmSignerKeyring returns an ExtendedAgent
func NewSSHAlgorithmSignerKeyring(sshAlgorithmSigners []SSHAlgorithmSigner, sshCertificates []SSHCertificate) (agent.ExtendedAgent, error) {
	return &sshAlgorithmSignerKeyring{
		sshAlgorithmSigners: sshAlgorithmSigners,
		sshCertificates:     sshCertificates,
	}, nil
}

func (r *sshAlgorithmSignerKeyring) RemoveAll() error {
	return fmt.Errorf("removing keys not allowed")
}

func (r *sshAlgorithmSignerKeyring) Remove(_ ssh.PublicKey) error {
	return fmt.Errorf("removing keys not allowed")
}

func (r *sshAlgorithmSignerKeyring) Lock(_ []byte) error {
	return fmt.Errorf("locking agent not allowed")
}

func (r *sshAlgorithmSignerKeyring) Unlock(_ []byte) error {
	return fmt.Errorf("unlocking agent not allowed")
}

func (r *sshAlgorithmSignerKeyring) Add(_ agent.AddedKey) error {
	return fmt.Errorf("adding new keys not allowed")
}

func (r *sshAlgorithmSignerKeyring) Signers() ([]ssh.Signer, error) {
	return nil, fmt.Errorf("signers not allowed")
}

// The keyring does not support any extensions
func (r *sshAlgorithmSignerKeyring) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

func (r *sshAlgorithmSignerKeyring) List() ([]*agent.Key, error) {
	var keys []*agent.Key

	// TODO: the go lang ssh cert implementation does not support forcing rsa-sha2-256-cert-v01@openssh.com or rsa-sha2-512-cert-v01@openssh.com
	// https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
	// To fix this we would need to replace the keyname in the certBlob with one of the names listed.
	// This seems to be fixed in a newer go version, when this is merged:
	// https://github.com/golang/go/issues/37278
	for _, certificate := range r.sshCertificates {
		keys = append(keys, &agent.Key{
			Format:  certificate.Certificate.Type(),
			Blob:    certificate.Certificate.Marshal(),
			Comment: "cert " + certificate.Comment})
	}

	for _, algorithmSigner := range r.sshAlgorithmSigners {
		keys = append(keys, &agent.Key{
			Format:  algorithmSigner.Signer.PublicKey().Type(),
			Blob:    algorithmSigner.Signer.PublicKey().Marshal(),
			Comment: "user " + algorithmSigner.Comment})
	}

	return keys, nil
}

func (r *sshAlgorithmSignerKeyring) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return r.SignWithFlags(key, data, 0)
}

func (r *sshAlgorithmSignerKeyring) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	wanted := key.Marshal()

	for _, sshAlgorithmSigner := range r.sshAlgorithmSigners {
		pubKeyBlob := sshAlgorithmSigner.Signer.PublicKey().Marshal()
		if bytes.Equal(pubKeyBlob, wanted) {
			if flags == 0 {
				return sshAlgorithmSigner.Signer.Sign(rand.Reader, data)
			}

			var algorithm string
			switch flags {
			case agent.SignatureFlagRsaSha256:
				algorithm = ssh.SigAlgoRSASHA2256
			case agent.SignatureFlagRsaSha512:
				algorithm = ssh.SigAlgoRSASHA2512
			default:
				return nil, fmt.Errorf("agent: unsupported signature flags: %d", flags)
			}
			return sshAlgorithmSigner.Signer.SignWithAlgorithm(rand.Reader, data, algorithm)
		}
	}

	return nil, errors.New("not found")
}
