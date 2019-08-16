package cves

// CVE info presnted to us by TS
// each agent can have 0 or more
type CVE struct {
	CVENumber       string `json:"cveNumber"`
	ReportedPackage string `json:"reportedPackage"`
	SystemPackage   string `json:"systemPackage"`
	VectorType      string `json:"vectortype"`
	Severity        string `json:"severity"`
	IsSuppressed    bool   `json:"isSuppressed"`
	NISTLink        string
	InstanceId      string
}

// CVEs is the full list of CVEs that TS
// shows for an agent
type CVEs struct {
	CVEs  []CVE
	Token string
}
