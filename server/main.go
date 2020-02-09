package server

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
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
	timestamp time.Time
	random    []byte
}

// CertificateRequest for SSH user certificate
type CertificateRequest struct {
	Challenge *Challenge     `json:"challenge"`
	Command   string         `json:"command"`
	Args      []string       `json:"args"`
	PublicKey string         `json:"publicKey"`
	Signature *ssh.Signature `json:"signature"`
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
	caKey ssh.Signer
}

// NewSigningServer creates a new server
func NewSigningServer(caKey ssh.Signer) *SigningServer {
	return &SigningServer{caKey: caKey}
}

// VerifyCertificateRequest errors if it fails validation
func (s *SigningServer) VerifyCertificateRequest(certRequest *CertificateRequest) (err error) {
	// Validate challenge came from us
	challenge := certRequest.Challenge
	err = s.caKey.PublicKey().Verify(challenge.Value, challenge.Signature)
	if err != nil {
		return err
	}

	// Unpack the value and ensure it's still valid
	var value challengeValue
	err = json.Unmarshal(challenge.Value, value)
	if err != nil {
		return err
	}

	// TODO: Check if challenge expired
	// TODO: Look up public key instead of parsing it
	userPubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certRequest.PublicKey))
	if err != nil {
		return err
	}

	payload := GenerateSigningPayload(certRequest)

	// Verify that public key signed it
	err = userPubkey.Verify(payload, certRequest.Signature)
	if err != nil {
		return err
	}

	return nil
}

// IssueUserCertificate issues ssh user certificate
func (s *SigningServer) IssueUserCertificate(userPublicKey ssh.PublicKey) (userCertificate *ssh.Certificate, err error) {
	userCert := &ssh.Certificate{
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
	payload = append(payload, certRequest.Command...)
	payload = append(payload, strings.Join(certRequest.Args, "")...)
	return payload
}

// GenerateChallenge creates a challenge payload for signing
func (s *SigningServer) GenerateChallenge() (challenge *Challenge, err error) {
	randomBytes, err := GenerateRamdomBytes(40)
	if err != nil {
		return nil, err
	}

	jsonBytes, err := json.Marshal(challengeValue{
		timestamp: time.Now(),
		random:    randomBytes,
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
