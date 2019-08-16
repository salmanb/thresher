package agents

import (
	"encoding/json"
	"fmt"

	"github.com/salmanb/thresher/apiclient"
	tsapi "github.com/threatstack/ts/api"
)

func GetAgentData(config tsapi.Config, apiendpoint, token string) ([]byte, error) {

	if token != "" {
		apiendpoint = fmt.Sprintf(apiendpoint+"&token=%s", token)
	}
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

func MarshalAgentList(b []byte) (*Agents, error) {
	var agents Agents
	err := json.Unmarshal(b, &agents)
	if err != nil {
		return nil, err
	}
	return &agents, nil
}
