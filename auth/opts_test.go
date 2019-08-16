package auth

import "testing"

func TestDecryptFile(t *testing.T) {
	_, err := decryptFile("../nonexistent.json", "json")
	if err == nil {
		t.Errorf("File decryption succeeded, but it should have failed")
	}
	_, err = decryptFile("../auth.json", "json")
	if err != nil {
		t.Errorf("File decryption failed: %v", err)
	}
}

func TestMarshalData(t *testing.T) {
	json := `{ "User": "user", "Key": "key", "Org": "org", "APIEndpoint": "http://www.example.com"  }`
	_, err := marshalData([]byte(json))
	if err != nil {
		t.Errorf("Unable to marshal json data into Opts: %v", err)
	}
	json = `{ "User": "user", "Key": "key", "Org": 1234  , "APIEndpoint": "http://www.example.com"}`
	_, err = marshalData([]byte(json))
	if err == nil {
		t.Errorf("Data marshal was expected to fail, but did not.")
	}
}

func TestNewOpts(t *testing.T) {
	_, err := New("../auth.json", "json", "http://www.example.com")
	if err != nil {
		t.Errorf("Unable to set Authentication options: %v", err)
	}
}
