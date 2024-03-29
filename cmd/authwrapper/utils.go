package main

import (
	"bufio"
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

	"golang.org/x/crypto/ssh"
)

var httpClient = &http.Client{Timeout: 10 * time.Second}

func runCommandWithSSHAgent(sshAuthSock string, command string, args []string) (exitCode int, err error) {

	os.Setenv("SSH_AUTH_SOCK", sshAuthSock)

	// Do string replacement for SSH_AUTH_SOCK
	for i, arg := range args {
		args[i] = strings.ReplaceAll(arg, "$SSH_AUTH_SOCK", sshAuthSock)
		args[i] = strings.ReplaceAll(args[i], "$$SSH_AUTH_SOCK", sshAuthSock)
	}

	return runCommand(command, args)
}

func startSigningServer(caPrivateKeyPath string, keyPassword string, authorizedKeysPath, address string, defaultLifetime time.Duration) (ssh.PublicKey, error) {
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
			return nil, fmt.Errorf("failed google.NewSSHSignerFromSigner: %v", err)
		}

		authorizedKeysLines, err := readLines(authorizedKeysPath)
		if err != nil {
			return nil, fmt.Errorf("failed readLines: %v", err)
		}

		allowedKeys, err := server.ParseAuthorizedKeys(authorizedKeysLines, defaultLifetime)
		if err != nil {
			return nil, fmt.Errorf("failed parse ParseAuthorizedKeys: %v", err)
		}

		go func() {
			log.Fatal(server.StartHTTPSigningServer(caSSHSigner, allowedKeys, address))
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

func httpJSONRequest(method string, url string, requestData interface{}, responseData interface{}, maxResponseSize int64) error {
	// Convert request to JSON and wrap in io.Reader
	var requestBody io.Reader
	if requestData != nil {
		jsonBytes, err := json.Marshal(requestData)
		if err != nil {
			return err
		}
		requestBody = bytes.NewReader(jsonBytes)
	}

	// Do Request and ready body
	httpRequest, err := http.NewRequest(method, url, requestBody)
	if err != nil {
		return err
	}
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return err
	}
	defer httpResponse.Body.Close()

	// Limit size of response body we read into memory
	limitedReader := &io.LimitedReader{R: httpResponse.Body, N: maxResponseSize}
	responseBody, err := ioutil.ReadAll(limitedReader)
	if err != nil {
		return err
	}

	if httpResponse.StatusCode != 200 {
		return fmt.Errorf("%s %s failed(%d): %s", method, url, httpResponse.StatusCode, responseBody)
	}

	// Convert JSON to object
	err = json.Unmarshal(responseBody, responseData)
	if err != nil {
		return fmt.Errorf("failed to parse JSON in '%s': %v", responseBody, err)
	}

	return nil
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}
