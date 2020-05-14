package google

// TODO: Make generic so it can be used with other key implementation

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/connectedcars/auth-wrapper/server"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type kmsKeyring struct {
	userPrivateKeyPath string
	caPrivateKeyPath   string
	userSSHSigner      ssh.Signer
	signingServerURL   string
	signingHTTPClient  *http.Client

	locked     bool
	passphrase []byte
}

var errLocked = errors.New("agent: locked")

// NewKMSKeyring returns an Agent that holds keys in memory.  It is safe
// for concurrent use by multiple goroutines.
func NewKMSKeyring(userPrivateKeyPath string, signingServerURL string) (sshAgent agent.ExtendedAgent, err error) {
	userPrivateKey, err := NewKMSSigner(userPrivateKeyPath, false)
	if err != nil {
		return nil, err
	}
	userSSHSigner, err := NewSSHSignerFromKMSSigner(userPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed NewSignerFromSigner from: %v", err)
	}

	signingHTTPClient := &http.Client{Timeout: 10 * time.Second}

	return &kmsKeyring{
		userPrivateKeyPath: userPrivateKeyPath,
		userSSHSigner:      userSSHSigner,
		signingHTTPClient:  signingHTTPClient,
		signingServerURL:   signingServerURL,
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

// List returns the identities known to the agent.
func (r *kmsKeyring) List() ([]*agent.Key, error) {
	var ids []*agent.Key

	userPublicKey := r.userSSHSigner.PublicKey()
	ids = append(ids, &agent.Key{
		Format:  userPublicKey.Type(),
		Blob:    userPublicKey.Marshal(),
		Comment: "user " + r.userPrivateKeyPath})

	if r.signingServerURL != "" {
		// GET /certificate/challenge # { value: "{ \"timestamp\": \"2020-01-01T10:00:00.000Z\" \"random\": \"...\"}", signature: "signed by CA key" }
		var challenge server.Challenge
		err := r.httpSignRequest("GET", "/certificate/challenge", nil, &challenge)
		if err != nil {
			return nil, err
		}

		// POST /certificate # { challenge: "\...value", command: "", args: "", pubkey: "..." signature: "signed by user key" }
		certRequest := &server.CertificateRequest{
			Challenge: &challenge,
			Command:   "some command", // TODO: Get command
			Args:      []string{},     // TODO: Get args
			PublicKey: string(ssh.MarshalAuthorizedKey(userPublicKey)),
		}
		// sign(challenge + command + args)
		certRequest.SignRequest(rand.Reader, r.userSSHSigner)

		// get back { certificate: "base64 encoded cert" }
		var certResponse server.CertificateResponse
		err = r.httpSignRequest("POST", "/certificate", certRequest, &certResponse)
		if err != nil {
			return nil, err
		}
		userCertPubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certResponse.Certificate))
		if err != nil {
			return nil, nil
		}
		userCert := userCertPubkey.(*ssh.Certificate)

		// TODO: the go lang ssh cert implementation does not support forcing rsa-sha2-256-cert-v01@openssh.com or rsa-sha2-512-cert-v01@openssh.com
		// https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
		// To fix this we would need to replace the keyname in the certBlob with one of the names listed.
		certBlob := userCert.Marshal()
		ids = append(ids, &agent.Key{
			Format:  userCert.Type(),
			Blob:    certBlob,
			Comment: "user cert " + r.userPrivateKeyPath})
	}

	return ids, nil
}

// Sign returns a signature for the data.
func (r *kmsKeyring) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return r.SignWithFlags(key, data, 0)
}

func (r *kmsKeyring) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	wanted := key.Marshal()

	if bytes.Equal(r.userSSHSigner.PublicKey().Marshal(), wanted) {
		// Ignore flags as they google key only supports one type of hashing.
		signature, err := r.userSSHSigner.Sign(rand.Reader, data)
		if err != nil {
			return nil, err
		}
		return signature, nil
	}

	return nil, errors.New("not found")
}

func (r *kmsKeyring) httpSignRequest(method string, url string, request interface{}, response interface{}) error {
	// Convert request to JSON and wrap in io.Reader
	var requestBody io.Reader
	if request != nil {
		jsonBytes, err := json.Marshal(request)
		if err != nil {
			return err
		}
		requestBody = bytes.NewReader(jsonBytes)
	}

	// Do Request and ready body
	challengeRequest, err := http.NewRequest(method, r.signingServerURL+url, requestBody)
	if err != nil {
		return err
	}
	challengeResponse, err := r.signingHTTPClient.Do(challengeRequest)
	if err != nil {
		return err
	}
	defer challengeResponse.Body.Close()
	responseBody, err := ioutil.ReadAll(challengeResponse.Body)
	if err != nil {
		return err
	}

	// Convert JSON to object
	err = json.Unmarshal(responseBody, response)
	if err != nil {
		return err
	}

	return nil
}
