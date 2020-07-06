package kms

import (
	"encoding/base64"
	"fmt"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudkms/v1"
	"net/http"
	"strings"
)

var CredJSON string

type CloudKMSClient struct {
	svc *cloudkms.Service
}

func New() (*CloudKMSClient, error) {
	ctx := context.Background()
	var client *http.Client
	if CredJSON != "" {
		cs, err := google.CredentialsFromJSON(ctx, []byte(CredJSON), cloudkms.CloudPlatformScope)
		if err != nil {
			return nil, fmt.Errorf("CredentialsFromJSON error err=%s", err.Error())
		}
		client = oauth2.NewClient(ctx, cs.TokenSource)
	}

	if client != nil {
		cc, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
		if err != nil {
			if strings.Contains(err.Error(), "could not find default credentials") {
				return nil, fmt.Errorf("Application Default Credentials (ADC) not found.\n" +
					"Either `gcloud auth application-default login` or set GOOGLE_APPLICATION_CREDENTIALS=/path/to/credentials.json (env variable)")
			}
		}
		client = cc
	}

	svc, err := cloudkms.New(client)
	if err != nil {
		return nil, err
	}
	return &CloudKMSClient{svc}, nil
}

func (client *CloudKMSClient) Encrypt(keyResourceID string, plaintext []byte) ([]byte, error) {
	res, err := client.svc.Projects.Locations.KeyRings.CryptoKeys.Encrypt(keyResourceID, &cloudkms.EncryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
	}).Do()
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(res.Ciphertext)
}

func (client *CloudKMSClient) Decrypt(keyResourceID string, ciphertext []byte) ([]byte, error) {
	res, err := client.svc.Projects.Locations.KeyRings.CryptoKeys.Decrypt(keyResourceID, &cloudkms.DecryptRequest{
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}).Do()
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(res.Plaintext)
}
