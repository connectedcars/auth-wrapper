package google

import (
	"crypto"
	"encoding/asn1"
	"io"
	"math/big"

	"golang.org/x/crypto/ssh"
)

type wrappedSigner struct {
	signer KMSSigner
	pubKey ssh.PublicKey
}

// NewSSHSignerFromKMSSigner takes a KMSSigner implementation and
// returns a corresponding ssh.Signer interface.
func NewSSHSignerFromKMSSigner(signer KMSSigner) (ssh.Signer, error) {
	pubKey, err := ssh.NewPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}
	return &wrappedSigner{signer, pubKey}, nil
}

func (s *wrappedSigner) PublicKey() ssh.PublicKey {
	return s.pubKey
}

func (s *wrappedSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.SignWithAlgorithm(rand, data)
}

func (s *wrappedSigner) SignWithAlgorithm(rand io.Reader, data []byte) (*ssh.Signature, error) {
	hashFunc := s.signer.Digest()

	var digest []byte
	if hashFunc != 0 {
		h := hashFunc.New()
		h.Write(data)
		digest = h.Sum(nil)
	} else {
		digest = data
	}

	signature, err := s.signer.Sign(rand, digest, hashFunc)
	if err != nil {
		return nil, err
	}

	var algorithm string
	if s.PublicKey().Type() == "ssh-rsa" {
		switch hashFunc {
		case crypto.SHA1:
			algorithm = ssh.SigAlgoRSA
		case crypto.SHA256:
			algorithm = ssh.SigAlgoRSASHA2256
		case crypto.SHA512:
			algorithm = ssh.SigAlgoRSASHA2512
		}
	} else {
		algorithm = s.pubKey.Type()
	}

	// crypto.Signer.Sign is expected to return an ASN.1-encoded signature
	// for ECDSA and DSA, but that's not the encoding expected by SSH, so
	// re-encode.
	switch s.pubKey.Type() {
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-dss":
		type asn1Signature struct {
			R, S *big.Int
		}
		asn1Sig := new(asn1Signature)
		_, err := asn1.Unmarshal(signature, asn1Sig)
		if err != nil {
			return nil, err
		}

		switch s.pubKey.Type() {
		case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
			signature = ssh.Marshal(asn1Sig)
		case "ssh-dss":
			signature = make([]byte, 40)
			r := asn1Sig.R.Bytes()
			s := asn1Sig.S.Bytes()
			copy(signature[20-len(r):20], r)
			copy(signature[40-len(s):40], s)
		}
	}

	return &ssh.Signature{
		Format: algorithm,
		Blob:   signature,
	}, nil
}
