package server

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"time"

	"golang.org/x/crypto/ssh"
)

// Challenge is a JSON structure for signing
type Challenge struct {
	Value     []byte         `json:"value"`
	Signature *ssh.Signature `json:"signature"`
}

type challengeValue struct {
	Timestamp string `json:"timestamp"`
	Random    []byte `json:"random"`
}

// CertificateRequest for SSH user certificate
type CertificateRequest struct {
	Challenge  *Challenge     `json:"challenge"`
	Principals []string       `json:"principals"`
	Command    string         `json:"command"`
	Args       []string       `json:"args"`
	PublicKey  string         `json:"publicKey"`
	Signature  *ssh.Signature `json:"signature"`
}

// SignRequest signs request with provided user key : Move to common lib as this is used by the client
func (s *CertificateRequest) SignRequest(rand io.Reader, userKey ssh.Signer) (err error) {
	payload := GenerateSigningPayload(s)
	signature, err := userKey.Sign(rand, payload)
	if err != nil {
		return err
	}
	s.Signature = signature
	return nil
}

// CertificateResponse is the signed user certificate
type CertificateResponse struct {
	Certificate string `json:"certificate"`
}

// SigningServer struct
type SigningServer struct {
	caKey          ssh.Signer
	allowedKeysMap map[string]*AllowedKey
}

// NewSigningServer creates a new server
func NewSigningServer(caKey ssh.Signer, allowedKeys []AllowedKey) *SigningServer {
	var allowedKeysMap = map[string]*AllowedKey{}
	for i, allowedKey := range allowedKeys {
		pubkeyString := strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(allowedKey.Key)), "\n")
		allowedKeysMap[pubkeyString] = &allowedKeys[i]
	}
	return &SigningServer{
		caKey:          caKey,
		allowedKeysMap: allowedKeysMap,
	}
}

// VerifyCertificateRequest errors if it fails validation
func (s *SigningServer) VerifyCertificateRequest(certRequest *CertificateRequest) (*AllowedKey, error) {
	// Validate challenge came from us
	challenge := certRequest.Challenge

	err := s.caKey.PublicKey().Verify(challenge.Value, challenge.Signature)
	if err != nil {
		return nil, err
	}

	// Unpack the value and ensure it's still valid
	var value challengeValue
	err = json.Unmarshal(challenge.Value, &value)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()

	// Check if challenge expired
	issueTimeStamp, err := time.Parse(time.RFC3339Nano, value.Timestamp)
	if err != nil {
		return nil, err
	}
	if issueTimeStamp.After(now.Add(30 * time.Second)) {
		return nil, fmt.Errorf("challenge expired")
	}

	// Fetch key from allowed map
	allowedKey := s.allowedKeysMap[certRequest.PublicKey]
	if allowedKey == nil {
		return nil, nil
	}

	// Disallowed if the key expired
	if allowedKey.ExpiresAt.Before(now) {
		return nil, fmt.Errorf("key expired")
	}

	payload := GenerateSigningPayload(certRequest)

	// Verify that public key signed it
	err = allowedKey.Key.Verify(payload, certRequest.Signature)
	if err != nil {
		return nil, err
	}

	return allowedKey, nil
}

// IssueUserCertificate issues ssh user certificate
func (s *SigningServer) IssueUserCertificate(allowedKey *AllowedKey, principals []string) (userCertificate *ssh.Certificate, err error) {
	userCert := &ssh.Certificate{
		Key:             allowedKey.Key,
		KeyId:           strconv.Itoa(allowedKey.Index),
		CertType:        ssh.UserCert,
		ValidPrincipals: principals,
		ValidAfter:      0,
		ValidBefore:     uint64(time.Now().Add(allowedKey.Lifetime).Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: allowedKey.Options,
			Extensions:      allowedKey.Extensions,
		},
	}

	// Sign and add a user certificate to the keyring
	err = userCert.SignCert(rand.Reader, s.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed SignCert from %v", err)
	}

	return userCert, err
}

// GenerateSigningPayload generates payload for signing
func GenerateSigningPayload(certRequest *CertificateRequest) (payload []byte) {
	challenge := certRequest.Challenge
	// Build the signed payload
	payload = challenge.Value
	payload = append(payload, challenge.Signature.Format...)
	payload = append(payload, challenge.Signature.Blob...)
	payload = append(payload, strings.Join(certRequest.Principals, ",")...)
	payload = append(payload, certRequest.Command...)
	payload = append(payload, strings.Join(certRequest.Args, ",")...)
	return payload
}

// GenerateChallenge creates a challenge payload for signing
func (s *SigningServer) GenerateChallenge() (challenge *Challenge, err error) {
	randomBytes, err := GenerateRamdomBytes(40)
	if err != nil {
		return nil, err
	}

	jsonBytes, err := json.Marshal(&challengeValue{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Random:    randomBytes,
	})

	if err != nil {
		return nil, err
	}

	signature, err := s.caKey.Sign(rand.Reader, jsonBytes)
	if err != nil {
		return nil, err
	}

	return &Challenge{Value: jsonBytes, Signature: signature}, nil
}
