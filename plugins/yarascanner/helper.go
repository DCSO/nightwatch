// Nightwatch
// Copyright (c) 2016, 2025, DCSO GmbH

package yarascanner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/hillu/go-yara/v4"
	log "github.com/sirupsen/logrus"
	"github.com/xi2/xz"
)

// loadRules tries to get a compiled yara rule file and
// sets it globally.
func loadRules(ruleFile string, isXz bool) error {
	var ruleReader io.Reader

	if ruleFile != "" {
		yLogger.Info("Loading rule file ", ruleFile)
		fileReader, err := os.Open(ruleFile)
		if err != nil {
			return err
		}

		if isXz {
			ruleReader, err = xz.NewReader(fileReader, 0)
			if err != nil {
				return err
			}
		} else {
			ruleReader = fileReader
		}

		scanRules, err = yara.ReadRules(ruleReader)
		if err != nil {
			return errors.New("error loading local yara plugin rule file")
		}
		log.Infof("Loaded [%d] rules", len(scanRules.GetRules()))
	} else {
		yLogger.Debug("Retrieving rule file via HTTP from: ", *ruleURI)
		response, err := http.Get(*ruleURI)
		if err != nil {
			return err
		}
		defer response.Body.Close()

		if isXz {
			ruleReader, err = xz.NewReader(response.Body, 0)
			if err != nil {
				return err
			}
		} else {
			data, err := io.ReadAll(response.Body)
			if err != nil {
				return err
			}
			ruleReader = bytes.NewReader(data)
		}

		scanRules, err = yara.ReadRules(ruleReader)
		if err != nil {
			return errors.New("error loading yara plugin rule file from server: " + fmt.Sprintf("%v", err))
		}
		log.Infof("Loaded [%d] rules", len(scanRules.GetRules()))
	}
	return nil
}

// YARAResults represents the subobject in the returned JSON that contains
// the YARA matches observed in the file
type YARAResults struct {
	MatchedRules []string               `json:"MatchedRules"`
	RuleDetails  map[string]interface{} `json:"RuleDetails"`
}

func matchToResults(m []yara.MatchRule) (string, error) {
	var res YARAResults
	res.MatchedRules = make([]string, 0)
	res.RuleDetails = make(map[string]interface{})
	for _, v := range m {
		res.MatchedRules = append(res.MatchedRules, v.Rule)
		res.RuleDetails[v.Rule] = v.Strings
	}

	out, err := json.Marshal(res)
	if err != nil {
		return "", err
	}

	return string(out[:]), nil
}
