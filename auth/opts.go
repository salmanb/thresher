package auth

import (
	"encoding/json"

	"go.mozilla.org/sops/decrypt"
)

// Opts holds values for authentication with TS API
type Opts struct {
	User        string
	Key         string
	Org         string
	APIEndpoint string
}

// New accepts a json file name or path for a SOPS encrypted json file,
// and parses it to read values for User, Key, and Org
func New(fp, format, apiendpoint string) (*Opts, error) {

	authbytes, err := decryptFile(fp, format)
	if err != nil {
		return nil, err
	}

	opts, err := marshalData(authbytes)
	if err != nil {
		return nil, err
	}

	opts.APIEndpoint = apiendpoint
	return opts, nil
}

// decrypt the file contents
func decryptFile(fp, format string) ([]byte, error) {
	fbytes, err := decrypt.File(fp, format)
	return fbytes, err
}

// marshal the data into a struct
func marshalData(b []byte) (*Opts, error) {
	var opts Opts
	err := json.Unmarshal(b, &opts)
	if err != nil {
		return nil, err
	}
	return &opts, nil
}
