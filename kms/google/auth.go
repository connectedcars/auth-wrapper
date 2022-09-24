package google

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"time"

	"golang.org/x/oauth2"
	googleauth "golang.org/x/oauth2/google"
)

func FindTokenSource() (oauth2.TokenSource, error) {
	tokenSource, errEnv := NewEnvTokenSource()
	if errEnv == nil && tokenSource != nil {
		return tokenSource, errEnv
	}
	tokenSource, errGcloud := NewGcloudTokenSource()
	if errGcloud == nil && tokenSource != nil {
		return tokenSource, errGcloud
	}
	return nil, fmt.Errorf("Failed to find credentials")
}

func NewEnvTokenSource() (oauth2.TokenSource, error) {
	credentials, err := googleauth.FindDefaultCredentials(context.Background(), "https://www.googleapis.com/auth/cloud-platform")
	if err == nil {
		// Try to get a token so we know it works
		token, err := credentials.TokenSource.Token()
		if err != nil {
			return nil, err
		}
		return oauth2.ReuseTokenSource(token, credentials.TokenSource), nil
	}
	return nil, fmt.Errorf("Failed to find credentials in the environment")
}

func NewGcloudTokenSource() (oauth2.TokenSource, error) {
	if _, err := exec.LookPath("gcloud"); err != nil {
		return nil, fmt.Errorf("Failed to find gcloud in path")
	}

	// Try to get a token so we know it works
	ts := gcloudTokenSource{}

	token, err := ts.Token()
	if err != nil {
		return nil, err
	}

	return oauth2.ReuseTokenSource(token, ts), nil
}

type gcloudTokenSource struct{}

type gcloudOutput struct {
	Credential struct {
		AccessToken string `json:"access_token"`
		TokenExpiry string `json:"token_expiry"`
		IdToken     string `json:"id_token"`
	} `json:"credential"`
}

func (gts gcloudTokenSource) Token() (*oauth2.Token, error) {
	gcloudCmd := exec.Command("gcloud", "config", "config-helper", "--force-auth-refresh", "--format=json(credential)")
	var out bytes.Buffer
	gcloudCmd.Stdout = &out
	gcloudCmd.Stderr = log.Writer()

	if err := gcloudCmd.Run(); err != nil {
		return nil, fmt.Errorf("error executing `gcloud config config-helper`: %w", err)
	}

	creds := gcloudOutput{}
	if err := json.Unmarshal(out.Bytes(), &creds); err != nil {
		return nil, fmt.Errorf("failed to parse `gcloud config config-helper` output: %w", err)
	}

	expiry, err := time.Parse(time.RFC3339, creds.Credential.TokenExpiry)
	if err != nil {
		return nil, fmt.Errorf("failed to parse gcloud token expiry: %w", err)
	}

	token := oauth2.Token{
		TokenType:   "Bearer",
		AccessToken: creds.Credential.AccessToken,
		Expiry:      expiry,
	}

	return &token, nil
}
