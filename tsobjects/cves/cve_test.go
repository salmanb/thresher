package cves

import (
	"testing"

	tsapi "github.com/threatstack/ts/api"
)

func TestGetCVE(t *testing.T) {
	_, err := GetCVEByAgentID(tsapi.Config{"user", "key", "org"}, "http://www.example.com")
	if err != nil {
		t.Errorf("Error while getting CVEs for Agent: %s", err)
	}
}

func TestParseCVEData(t *testing.T) {
	jsondata := `{"cves":[{"cveNumber":"CVE-2018-14036","reportedPackage":"accountsservice 0.6.35","systemPackage":"accountsservice 0.6.35-0ubuntu7.3","vectorType":"network","severity":"medium","isSuppressed":true}], "token": null}`
	_, err := ParseCVEData([]byte(jsondata))
	if err != nil {
		t.Errorf("Error while parsing CVE data for Agent: %s", err)
	}
}
