package sshagent

import (
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// StartSSHAgentServer start an SSH Agent server and loads the given private key
func StartSSHAgentServer(sshAgent agent.Agent) (sshAuthSock string, error error) {
	// Generate random filename
	dir, err := ioutil.TempDir(os.TempDir(), "")
	if err != nil {
		log.Fatal(err)
	}
	sshAuthSock = dir + "/" + generateRandomString(8) + ".sock"

	go func() {
		// Open SSH agent socket
		if err := os.RemoveAll(sshAuthSock); err != nil {
			log.Fatal(err)
		}
		l, err := net.Listen("unix", sshAuthSock)
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()

		// Accept new connections, dispatching them to an ssh agent server in the background
		for {
			conn, err := l.Accept()
			if err != nil {
				log.Fatal("accept error:", err)
			}
			go agent.ServeAgent(sshAgent, conn)
		}
	}()

	return sshAuthSock, err
}

// ConnectSSHAgent connects to a SSH agent socket and returns a agent.ExtendedAgent
func ConnectSSHAgent(socket string) (agent.ExtendedAgent, error) {
	conn, err := net.Dial("unix", string(socket))
	if err != nil {
		return nil, fmt.Errorf("net.Dial: %v", err)
	}
	return agent.NewClient(conn), nil
}

const letterBytes = "abcdefghijklmnopqrstuvwxyz"

func generateRandomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

// ParsePrivateSSHKey parses a private key
func ParsePrivateSSHKey(privateKeyBytes []byte, passphrase string) (interface{}, error) {
	var err error
	var privateKey interface{}
	if strings.Contains(string(privateKeyBytes), "ENCRYPTED") {
		privateKey, err = ssh.ParseRawPrivateKeyWithPassphrase(privateKeyBytes, []byte(passphrase))
		if err != nil {
			return nil, err
		}
	} else {
		privateKey, err = ssh.ParseRawPrivateKey(privateKeyBytes)
		if err != nil {
			return nil, err
		}
	}

	return privateKey, nil
}
