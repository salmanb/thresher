package cves

import (
	"encoding/json"

	"github.com/salmanb/thresher/apiclient"
	tsapi "github.com/threatstack/ts/api"
)

// GetCVEByAgentID pulls list of CVEs from the TS API for specific agents
// AgentID is expected as part of the apiendpoint URL string
func GetCVEByAgentID(config tsapi.Config, apiendpoint string) ([]byte, error) {
	req, err := apiclient.NewHttpReq(config, apiendpoint)
	if err != nil {
		return nil, err
	}
	body, err := apiclient.GetData(req)
	if err != nil {
		return nil, err
	}

	return body, nil
}

func ParseCVEData(b []byte) (CVEs, error) {
	var cves CVEs
	err := json.Unmarshal(b, &cves)
	if err != nil {
		return cves, err
	}

	return cves, nil
}
