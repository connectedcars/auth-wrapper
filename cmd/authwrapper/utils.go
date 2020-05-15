package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/connectedcars/auth-wrapper/kms/google"
	"github.com/connectedcars/auth-wrapper/server"
	"github.com/connectedcars/auth-wrapper/sshagent"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var httpClient = &http.Client{Timeout: 10 * time.Second}

func runCommandWithSSHAgent(agent agent.ExtendedAgent, command string, args []string) (exitCode int, err error) {
	sshAuthSock, err := sshagent.StartSSHAgentServer(agent)
	if err != nil {
		return 255, fmt.Errorf("Failed to start ssh agent server: %v", err)
	}
	os.Setenv("SSH_AUTH_SOCK", sshAuthSock)

	// Do string replacement for SSH_AUTH_SOCK
	for i, arg := range args {
		args[i] = strings.ReplaceAll(arg, "$SSH_AUTH_SOCK", sshAuthSock)
		args[i] = strings.ReplaceAll(args[i], "$$SSH_AUTH_SOCK", sshAuthSock)
	}

	return runCommand(command, args)
}

func startSigningServer(caPrivateKeyPath string, sshCaKeyPassword string, address string) (ssh.PublicKey, error) {
	var caPublicKey ssh.PublicKey
	if strings.HasPrefix(caPrivateKeyPath, "kms://") {
		var err error
		kmsCaPrivateKeyPath := caPrivateKeyPath[6:]

		// Start the signing server
		caPrivateKey, err := google.NewKMSSigner(kmsCaPrivateKeyPath, false)
		if err != nil {
			return nil, fmt.Errorf("failed google.NewKMSSigner %v", err)
		}
		caSSHSigner, err := google.NewSSHSignerFromSigner(caPrivateKey, caPrivateKey.Digest())
		if err != nil {
			return nil, fmt.Errorf("failed google.NewSignerFromSigner from: %v", err)
		}

		go func() {
			log.Fatal(server.StartHTTPSigningServer(caSSHSigner, address))
		}()
		caPublicKey = caSSHSigner.PublicKey()

	} else {
		return nil, fmt.Errorf("Not implemented yet")
	}

	return caPublicKey, nil
}

func runCommand(command string, args []string) (exitCode int, err error) {
	cmd := exec.Command(command, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return 1, fmt.Errorf("cmd.Start: %v", err)
	}

	err = cmd.Wait()
	if err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				return status.ExitStatus(), nil
			}
			return 1, fmt.Errorf("Failed to get status code: %v", err)
		}
		return 1, fmt.Errorf("cmd.Wait: %v", err)
	}
	return 0, nil
}

func httpJSONRequest(method string, url string, request interface{}, response interface{}) error {
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
	challengeRequest, err := http.NewRequest(method, url, requestBody)
	if err != nil {
		return err
	}
	challengeResponse, err := httpClient.Do(challengeRequest)
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
