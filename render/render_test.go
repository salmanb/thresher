package render

import (
	"fmt"
	"testing"
	"time"

	"github.com/salmanb/thresher/tsobjects/cves"
)

func TestRender(t *testing.T) {
	cves := cves.CVEs{
		CVEs: []cves.CVE{
			cves.CVE{
				CVENumber:       "CVE-2048",
				ReportedPackage: "net-utils",
				SystemPackage:   "net-utils",
				VectorType:      "local",
				Severity:        "Critical",
				IsSuppressed:    true,
			},
		},
	}

	instanceid := "i-298lasd928"
	now := time.Now()
	year, month, day := now.Date()
	dest := fmt.Sprintf("%s/%d-%d-%d", "/tmp/", year, month, day)

	w := Wheat{
		CVEs:        cves,
		InstanceID:  instanceid,
		Destination: dest,
		TmplFile:    "tpl/inventory.gohtml",
	}

	err := w.MakeDatedDir()
	if err != nil {
		t.Errorf("Failed while creating new dated directory: %s", err)
	}

	err = w.WriteCVEdata(fmt.Sprintf("%s/%s.html", w.Destination, w.InstanceID))
	if err != nil {
		t.Errorf("Failed while creating new dated directory: %s", err)
	}

}
