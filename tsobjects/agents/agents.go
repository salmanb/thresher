package agents

type Tag struct {
	Key    string
	Value  string
	Source string
}

type Agent struct {
	ID          string
	InstanceID  string
	Name        string
	IPAddresses map[string][]string
	Tags        []Tag
}

type Agents struct {
	Agents []Agent
	Token  string
}
