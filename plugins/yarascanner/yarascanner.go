// Nightwatch
// Copyright (c) 2016, 2025, DCSO GmbH

package yarascanner

import (
	"flag"
	"time"

	"github.com/DCSO/nightwatch/registry"

	"github.com/hillu/go-yara/v4"
	log "github.com/sirupsen/logrus"
)

var (
	scanRules *yara.Rules
	ruleFile  = flag.String("rule-file", "", "Path for compiled YARA rule file")
	ruleURI   = flag.String("rule-uri", "http://localhost/yara/current.yac", "Download URL for YARA rules")
	ruleXZ    = flag.Bool("rule-xz", false, "YARA rules are XZ compressed")
	yLogger   = log.WithFields(log.Fields{"plugin": "YARA"})
)

func init() {
	my := &Scanner{}
	registry.RegisterAnalysisPlugin(my)
}

// Scanner is the helper struct to implement the registry interface
type Scanner struct{}

// Name returns the plugin name
func (y *Scanner) Name() string { return "YARA" }

// ReInitialize loads the yara rules either from file or url
func (y *Scanner) ReInitialize() error {
	return loadRules(*ruleFile, *ruleXZ)
}

// ProcessFile is the main scanning routine
func (y *Scanner) ProcessFile(sample registry.FileSample) (string, bool, error) {
	var suspicious bool
	var reason string
	var matchRules yara.MatchRules

	err := scanRules.ScanFileDescriptor(sample.FD, yara.ScanFlags(yara.ScanFlagsFastMode), time.Second*20, &matchRules)
	if err != nil {
		return "", false, err
	}

	if len(matchRules) != 0 {
		reason, err = matchToResults(matchRules)
		if err != nil {
			return "", false, err
		}
		yLogger.Warningf("Matches for file %v found", sample.Info.Name())
		suspicious = true
	}
	yLogger.Debug("Processed file:", sample.Info.Name())
	return reason, suspicious, nil
}
