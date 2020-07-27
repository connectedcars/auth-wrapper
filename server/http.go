package server

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// StatusError is returned for http errors
type StatusError struct {
	Code int
	Err  error
}

// HTTPSigningServer is a http server
type HTTPSigningServer struct {
	signingServer *SigningServer
}

// StartHTTPSigningServer returns a HTTPSigningServer
func StartHTTPSigningServer(caKey ssh.Signer, allowedKeys []AllowedKey, listenAddr string) error {
	signingServer := NewSigningServer(caKey, allowedKeys)

	httpSigningServer := &HTTPSigningServer{signingServer: signingServer}

	http.Handle("/", httpSigningServer)
	err := http.ListenAndServe(listenAddr, nil)
	if err != nil {
		return err
	}
	return nil
}

func (s *HTTPSigningServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	location := r.Method + " " + r.URL.Path

	var errorStatus *StatusError
	var jsonResponse interface{}
	switch location {
	case "GET /certificate/challenge":
		jsonResponse, errorStatus = s.getCertificateChallenge(w, r)
	case "POST /certificate":
		jsonResponse, errorStatus = s.postCertificate(w, r)
	default:
		http.Error(w, "Not found", 400)
	}
	if errorStatus != nil {
		http.Error(w, errorStatus.Err.Error(), errorStatus.Code)
	}

	if jsonResponse != nil {
		jsonBytes, err := json.Marshal(jsonResponse)
		if err != nil {
			http.Error(w, err.Error(), 500)
		}
		w.Write(jsonBytes)
	}
}

func (s *HTTPSigningServer) getCertificateChallenge(w http.ResponseWriter, r *http.Request) (jsonResponse interface{}, statusError *StatusError) {
	challenge, err := s.signingServer.GenerateChallenge()
	if err != nil {
		return nil, &StatusError{500, err}
	}
	return challenge, nil
}

func (s *HTTPSigningServer) postCertificate(w http.ResponseWriter, r *http.Request) (jsonResponse interface{}, statusError *StatusError) {
	defer r.Body.Close()

	// Limit how much of the body we read in a request
	limitedReader := &io.LimitedReader{R: r.Body, N: 1 * 1024 * 1024}

	body, err := ioutil.ReadAll(limitedReader)
	if err != nil {
		return nil, &StatusError{500, err}
	}

	var certRequest CertificateRequest
	err = json.Unmarshal(body, &certRequest)
	if err != nil {
		return nil, &StatusError{400, err}
	}

	// Validate CertificateRequest input
	if certRequest.Challenge == nil {
		return nil, &StatusError{400, fmt.Errorf("challenge not set")}
	}
	if certRequest.Principals == nil {
		return nil, &StatusError{400, fmt.Errorf("principals not set")}
	}
	if certRequest.Signature == nil {
		return nil, &StatusError{400, fmt.Errorf("signature not set")}
	}
	if certRequest.Args == nil {
		return nil, &StatusError{400, fmt.Errorf("args not set")}
	}

	// Validate certRequest.Challenge
	if certRequest.Challenge.Signature == nil {
		return nil, &StatusError{400, fmt.Errorf("challenge.signature not set")}
	}
	if certRequest.Challenge.Value == nil {
		return nil, &StatusError{400, fmt.Errorf("challenge.value not set")}
	}

	// Check if this request is allowed
	allowedKey, err := s.signingServer.VerifyCertificateRequest(&certRequest)
	if err != nil {
		return nil, &StatusError{400, err}
	}
	if allowedKey == nil {
		return nil, &StatusError{401, fmt.Errorf("Key not allowed")}
	}

	// Check requested principals are allowed
	for _, requestedPrincipal := range certRequest.Principals {
		for i, allowedPrincipal := range allowedKey.Principals {
			match, err := filepath.Match(allowedPrincipal, requestedPrincipal)
			if err != nil {
				return nil, &StatusError{500, fmt.Errorf("allowed pattern is malformed")}
			}
			if match {
				break
			}
			if i == len(allowedKey.Principals)-1 {
				return nil, &StatusError{400, fmt.Errorf("requested principal '%s' not allowed", requestedPrincipal)}
			}
		}
	}

	// TODO: Check if command is allowed https://github.com/tlbdk/socketauth/blob/master/src/sshutils.test.js
	// TODO: Add SSH command to Options so we are sure only that command will be run

	userCert, err := s.signingServer.IssueUserCertificate(allowedKey, certRequest.Principals)
	if err != nil {
		return nil, &StatusError{500, err}
	}

	userCertString := ssh.MarshalAuthorizedKey(userCert)
	return &CertificateResponse{Certificate: string(userCertString)}, nil
}
