package kms

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudkms/v1"
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
		fmt.Printf("Exist CredJSON = %s\n", CredJSON)
		client = oauth2.NewClient(ctx, cs.TokenSource)
		fmt.Printf("client = %#v\n", client)
	}

	if client == nil {
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
	fmt.Printf("in CloudKMSClient.Decrypt keyResourceID=%v, ciphertext=%v\n", keyResourceID, ciphertext)
	res, err := client.svc.Projects.Locations.KeyRings.CryptoKeys.Decrypt(keyResourceID, &cloudkms.DecryptRequest{
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}).Do()
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(res.Plaintext)
}
