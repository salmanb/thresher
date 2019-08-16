package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/salmanb/thresher/apiclient"
	"github.com/salmanb/thresher/auth"
	"github.com/salmanb/thresher/render"
	"github.com/salmanb/thresher/tsobjects/agents"
	"github.com/salmanb/thresher/tsobjects/cves"

	tsapi "github.com/threatstack/ts/api"
)

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("Destination directory path, or tags not specified.\n Usage: %s /path tag1 tag2 tag3...", os.Args[0])
	}
	now := time.Now()
	year, month, day := now.Date()
	destdir := fmt.Sprintf("%s/%d-%d-%d", os.Args[1], year, month, day)
	tags := make(map[string]string)

	for _, v := range os.Args[3:] {
		tags[v] = v
	}

	authopts, err := auth.New("auth.json", "json", "https://api.threatstack.com/v2/agents?status=online&type=investigate")
	if err != nil {
		log.Fatalf("Could not initialize auth opts: %s", err)
	}
	tsconfig := tsapi.Config{
		User: authopts.User,
		Key:  authopts.Key,
		Org:  authopts.Org,
	}

	agentbytes, err := agents.GetAgentData(tsconfig, authopts.APIEndpoint, "")
	if err != nil {
		log.Fatalf("Could not get agent data: %s", err)
	}
	agentlist, err := agents.MarshalAgentList(agentbytes)
	if err != nil {
		if err == err.(*apiclient.RatelimitError) {
			log.Println(err)
			fmt.Println("Sleeping for 120 seconds to reset rate limit")
			time.Sleep(120 * time.Second)
		} else {
			log.Fatalf("HTTP error encountered: %s", err)
		}
	}
	for agentlist.Token != "" {
		agentbytes, err = agents.GetAgentData(tsconfig, authopts.APIEndpoint, agentlist.Token)
		if err != nil {
			log.Fatalf("Unable to get Agent data: %s", err)
		}
		agentlist, err = agents.MarshalAgentList(agentbytes)
		if err != nil {
			log.Fatalf("Unable to marshal Agent data: %s", err)
		}
		for i := range agentlist.Agents {
			processAgent := true
			for _, tval := range agentlist.Agents[i].Tags {
				// check if all the tags that the user passed are associated with this agent
				// if not, don't process the agent
				if _, ok := tags[tval.Value]; !ok {
					processAgent = false
					break
				}
				if processAgent {
					fmt.Printf("Agent ID: %v\n", agentlist.Agents[i].ID)
					fmt.Printf("Agent InstanceID: %v\n", agentlist.Agents[i].InstanceID)
					cvedata, err := cves.GetCVEByAgentID(tsconfig, fmt.Sprintf("https://api.threatstack.com/v2/vulnerabilities?agentId=%s", agentlist.Agents[i].ID))
					if err != nil {
						if err == err.(*apiclient.RatelimitError) {
							log.Println(err)
							fmt.Println("Sleeping for 120 seconds to reset rate limit")
							time.Sleep(120 * time.Second)
							cvedata, err = cves.GetCVEByAgentID(tsconfig, fmt.Sprintf("https://api.threatstack.com/v2/vulnerabilities?agentId=%s", agentlist.Agents[i].ID))
						} else if err == err.(*apiclient.NotFoundError) {
							fmt.Printf("CVE data not found for %s\n", agentlist.Agents[i].InstanceID)
							continue
						} else {
							log.Printf("%T\n", err)
							log.Fatalf("Unable to get CVE data: %v", err)
						}
					}
					cvelist, err := cves.ParseCVEData(cvedata)
					if err != nil {
						log.Fatalf("Unable to parse CVE data for agent %s, %s", agentlist.Agents[i].ID, err)
					}
					if len(cvelist.CVEs) > 0 {
						w := render.Wheat{
							CVEs:        cvelist,
							InstanceID:  agentlist.Agents[i].InstanceID,
							Destination: destdir,
							TmplFile:    "render/tpl/inventory.gohtml",
						}
						err := w.MakeDatedDir()
						if err != nil {
							log.Fatalf("Failed to create %s: %s", w.Destination, err)
						}
						err = w.WriteCVEdata(fmt.Sprintf("%s/%s.html", w.Destination, w.InstanceID))
						if err != nil {
							log.Fatalf("Unable to display CVE data: %s", err)
						}
					}
				}
			}
		}
	}
}
