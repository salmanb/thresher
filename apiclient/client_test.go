package apiclient

import (
	"testing"

	"github.com/salmanb/thresher/auth"
	tsapi "github.com/threatstack/ts/api"
)

func TestNewClientConfig(t *testing.T) {
	opts := &auth.Opts{
		User:        "user",
		Key:         "key",
		Org:         "org",
		APIEndpoint: "http://www.example.com",
	}
	_, err := NewClientConfig(opts)
	if err != nil {
		t.Errorf("Unable to create a new config for API Client: %s", err)
	}
}
func TestNewClientReq(t *testing.T) {
	opts := &auth.Opts{
		User:        "user",
		Key:         "key",
		Org:         "org",
		APIEndpoint: "http://www.example.com",
	}
	config := tsapi.Config{
		User: opts.User,
		Key:  opts.Key,
		Org:  opts.Org,
	}
	req, err := NewHttpReq(config, opts.APIEndpoint)
	if err != nil {
		t.Errorf("Unable to instantiate a new HTTP Request: %s", err)
	}

	_, err = GetData(req)
	if err != nil {
		t.Errorf("Unable to make HTTP request: %s", err)
	}
}
