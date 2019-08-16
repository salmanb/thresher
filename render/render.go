package render

import (
	"fmt"
	"html/template"
	"log"
	"os"

	"github.com/salmanb/thresher/tsobjects/cves"
)

type Wheat struct {
	CVEs        cves.CVEs
	InstanceID  string
	Destination string
	TmplFile    string
}

// MakeDatedDir creates a directory by formatting t as 'YYYY-MM-DD'
// and creating a directory with that /destination/YYYY-MM-DD
func (w *Wheat) MakeDatedDir() error {
	if _, err := os.Stat(w.Destination); os.IsNotExist(err) {
		err = os.MkdirAll(w.Destination, 0755)
		if err != nil {
			return fmt.Errorf("could not create destination directory %s: %s", w.Destination, err)
		}
	}

	return nil
}

// DisplayCVEData by stepping through the list of CVEs
func (w *Wheat) WriteCVEdata(fp string) error {

	for i := range w.CVEs.CVEs {
		if w.CVEs.CVEs[i].CVENumber == "" {
			return fmt.Errorf("no CVE number found for listed CVE -- item number %d in list", i)
		}
		w.CVEs.CVEs[i].NISTLink = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", w.CVEs.CVEs[i].CVENumber)
		// fmt.Printf("Reported Package: %s\n", cves.CVEs[i].ReportedPackage)
		// fmt.Printf("Vector Type: %s\n", cves.CVEs[i].VectorType)
		// fmt.Printf("Suppressed: %v\n", cves.CVEs[i].IsSuppressed)
		// fmt.Printf("== CVE Number: %s ==\n", cves.CVEs[i].CVENumber)
		// fmt.Printf("System Package: %s, ", cves.CVEs[i].SystemPackage)
		// fmt.Printf("Severity: %s, ", cves.CVEs[i].Severity)
		// fmt.Printf("NIST URL: %v\n", cves.CVEs[i].NISTLink)
		// fmt.Println("== ==")
	}

	tpl, err := template.ParseFiles(w.TmplFile)
	if err != nil {
		return err
	}

	out := fmt.Sprintf("%s/%s.html", w.Destination, w.InstanceID)
	log.Printf("Writing CVE data for %s to %s", w.InstanceID, out)
	f, err := os.OpenFile(out, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	defer f.Close()

	err = tpl.Execute(f, w)
	if err != nil {
		return err
	}
	return nil
}
