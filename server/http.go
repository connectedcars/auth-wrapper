package server

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

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
func StartHTTPSigningServer(caKey ssh.Signer, listenAddr string) error {
	signingServer := NewSigningServer(caKey)
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
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, &StatusError{500, err}
	}

	var certRequest CertificateRequest
	err = json.Unmarshal(body, &certRequest)
	if err != nil {
		return nil, &StatusError{400, err}
	}

	userPublickey, err := s.signingServer.VerifyCertificateRequest(&certRequest)
	if err != nil {
		return nil, &StatusError{400, err}
	}

	userCert, err := s.signingServer.IssueUserCertificate(userPublickey)
	if err != nil {
		return nil, &StatusError{500, err}
	}

	userCertString := ssh.MarshalAuthorizedKey(userCert)
	return &CertificateResponse{Certificate: string(userCertString)}, nil
}
