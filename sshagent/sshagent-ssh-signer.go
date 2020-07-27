package sshagent

import (
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type sshAgentSigner struct {
	agent agent.ExtendedAgent
	key   *agent.Key
}

// NewSSHAlgorithmSigner returns ssh signer
func NewSSHAlgorithmSigner(agent agent.ExtendedAgent, key *agent.Key) ssh.AlgorithmSigner {
	return &sshAgentSigner{
		agent: agent,
		key:   key,
	}
}

func (s *sshAgentSigner) PublicKey() ssh.PublicKey {
	return s.key
}

func (s *sshAgentSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.agent.Sign(s.key, data)
}

func (s *sshAgentSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	var flags agent.SignatureFlags
	switch algorithm {
	case ssh.SigAlgoRSASHA2256:
		flags = agent.SignatureFlagRsaSha256
	case ssh.SigAlgoRSASHA2512:
		flags = agent.SignatureFlagRsaSha512
	default:
		return nil, fmt.Errorf("unsupported signature algorithm: %s", algorithm)
	}
	return s.agent.SignWithFlags(s.key, data, flags)
}
