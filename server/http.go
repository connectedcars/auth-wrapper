package server

import (
	"net/http"

	"golang.org/x/crypto/ssh"
)

// HTTPSigningServer is a http server
type HTTPSigningServer struct {
	signingServer *SigningServer
}

// NewHTTPSigningServer returns a HTTPSigningServer
func NewHTTPSigningServer(caKey ssh.Signer) (httpSigningServer *HTTPSigningServer, err error) {
	signingServer := NewSigningServer(caKey)
	httpSigningServer = &HTTPSigningServer{signingServer: signingServer}

	http.Handle("/", httpSigningServer)
	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		return nil, err
	}
	return httpSigningServer, nil
}

func (s *HTTPSigningServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	location := r.Method + " " + r.URL.Path

	switch location {
	case "GET /certificate/challenge":
		s.getCertificateChallenge(w, r)
	case "POST /certificate":
		s.postCertificate(w, r)
	}

}

func (s *HTTPSigningServer) getCertificateChallenge(w http.ResponseWriter, r *http.Request) {

}

func (s *HTTPSigningServer) postCertificate(w http.ResponseWriter, r *http.Request) {

}
