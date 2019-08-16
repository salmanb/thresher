package agents

import (
	"testing"

	tsapi "github.com/threatstack/ts/api"
)

func TestGetAgentData(t *testing.T) {

	_, err := GetAgentData(tsapi.Config{"user", "key", "org"}, "http://www.example.com", "")
	if err != nil {
		t.Errorf("Unable to get a list of agents: %s", err)
	}
}

func TestMarshalAgentData(t *testing.T) {

	agent := `{"agents": [{
		"id": "80a99491-a809-11e9-9157-9307bdf9f951",
		"instanceId": "i-0104fac1333303e7e",
		"status": "online",
		"createdAt": "2019-07-16T20:37:17.828Z",
		"lastReportedAt": "2019-07-16T20:42:33.513Z",
		"version": "1.9.0",
		"name": "hostname.tld",
		"description": "",
		"hostname": "hostname.tld",
		"ipAddresses": {
			"private": [
				"172.21.119.161"
			],
			"link_local": [
				"fe80::824:6ff:fe23:c8f6"
			],
			"public": [
				"23.21.118.191",
				"3.91.78.236"
			]
		},
		"tags": [
			{
				"source": "ec2",
				"key": "aws:ec2launchtemplate:version",
				"value": "3"
			},
			{
				"source": "ec2",
				"key": "aws:ec2launchtemplate:id",
				"value": "lt-09efd4647e909bbec"
			},
			{
				"source": "ec2",
				"key": "Environment",
				"value": "production-east-1"
			},
			{
				"source": "ec2",
				"key": "Name",
				"value": "hostname.tld"
			},
			{
				"source": "ec2",
				"key": "Datadog",
				"value": "monitored"
			},
			{
				"source": "ec2",
				"key": "AutoscalingGroup",
				"value": "w-prod-01-data-11374-1d"
			},
			{
				"source": "ec2",
				"key": "Application",
				"value": "platform"
			},
			{
				"source": "ec2",
				"key": "Terraform",
				"value": "true"
			},
			{
				"source": "ec2",
				"key": "aws:autoscaling:groupName",
				"value": "w-prod-01-data-11374-1d"
			},
			{
				"source": "ec2",
				"key": "Service",
				"value": "sidekiq"
			},
			{
				"source": "ec2",
				"key": "CostCenter",
				"value": "us-east"
			}
		],
		"agentType": "investigate",
		"osVersion": "ubuntu 14.04",
		"kernel": "4.4.0-1042-aws"
	}],
	"token": "sometoken111111"}`

	agents, err := MarshalAgentList([]byte(agent))
	if err != nil {
		t.Errorf("Unable to marshal agent data: %s", err)
	}

	if agents.Agents[0].ID != "80a99491-a809-11e9-9157-9307bdf9f951" {
		t.Errorf("Expected Agent Id: %s - got %v", "80a99491-a809-11e9-9157-9307bdf9f951", agents.Agents[0].ID)
	}
	if agents.Token != "sometoken111111" {
		t.Errorf("Expected Token: %s - got %v", "sometoken111111", agents.Token)

	}
}
