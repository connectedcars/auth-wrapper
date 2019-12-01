package gcemetadata

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

// Links
// * https://github.com/googleapis/google-cloud-go/blob/master/compute/metadata/metadata.go

// StartMetadateServer start metadata server
func StartMetadateServer(proxyURL string) {
	if proxyURL != "" {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			// Copy request data and do request
			req, err := http.NewRequest(r.Method, proxyURL+r.RequestURI, r.Body)
			for name, value := range r.Header {
				req.Header.Set(name, value[0])
			}
			client := &http.Client{}
			resp, err := client.Do(req)
			r.Body.Close()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Copy
			for k, v := range resp.Header {
				w.Header().Set(k, v[0])
			}
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
			resp.Body.Close()
		})
	} else {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(os.Stderr, "req: %s\n", r.RequestURI)
			switch r.URL.Path {
			case "/computeMetadata/v1/project/project-id":
				projectID, err := gcloudGetValue("config", "list", "--format", "value(core.project)")
				if err != nil {
					log.Fatal(err)
				}
				metadataResponse(w, http.StatusOK, projectID)
			case "/computeMetadata/v1/project/numeric-project-id":
				projectID, err := gcloudGetValue("config", "list", "--format", "value(core.project)")
				if err != nil {
					log.Fatal(err)
				}
				projectNumber, err := gcloudGetValue("projects", "describe", projectID, "--format", "value(projectNumber)")
				if err != nil {
					log.Fatal(err)
				}
				metadataResponse(w, http.StatusOK, projectNumber)
			case "/computeMetadata/v1/instance/service-accounts/default/token":
				token, err := gcloudGetValue("auth", "print-access-token")
				if err != nil {
					log.Fatal(err)
				}
				metadataResponse(w, http.StatusOK, `{"access_token":"`+token+`","expires_in":3487,"token_type":"Bearer"}`)
			default:
				metadataResponse(w, http.StatusNotFound, `Not found`)
			}
		})
	}
	go func() {
		log.Fatal(http.ListenAndServe(":80", nil))
	}()
}

/* < Metadata-Flavor: Google
< Content-Type: application/text
< ETag: b2830b5c81343278
< Date: Fri, 22 Nov 2019 20:28:02 GMT
< Server: Metadata Server for VM
< Content-Length: 12
< X-XSS-Protection: 0
< X-Frame-Options: SAMEORIGIN
*/
func metadataResponse(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/text")
	w.Header().Set("Server", "Metadata Server for VM")
	w.WriteHeader(statusCode)
	fmt.Fprintf(w, "%s", message)
}

func gcloudGetValue(args ...string) (value string, err error) {
	out, err := exec.Command("gcloud", args...).Output()
	if err != nil {
		return "", err
	}
	value = strings.TrimSpace(strings.TrimRight(string(out), "\r\n"))
	return value, nil
}
