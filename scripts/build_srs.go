package main

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type SRS struct {
	Version int       `json:"version"`
	Rules   []SRSRule `json:"rules"`
}

type SRSRule struct {
	DomainSuffix  []string `json:"domain_suffix,omitempty"`
	DomainKeyword []string `json:"domain_keyword,omitempty"`
	DomainRegex   []string `json:"domain_regex,omitempty"`
	Domain        []string `json:"domain,omitempty"`
	IPCIDR        []string `json:"ip_cidr,omitempty"`
}

func main() {
	domainFiles, _ := filepath.Glob("../src/domains/*.txt")
	for _, file := range domainFiles {
		compileSRS(file, false)
	}

	ipFiles, _ := filepath.Glob("../src/ips/*.txt")
	for _, file := range ipFiles {
		compileSRS(file, true)
	}
}

func compileSRS(file string, isIP bool) {
	tag := strings.TrimSuffix(filepath.Base(file), ".txt")
	f, _ := os.Open(file)
	scanner := bufio.NewScanner(f)
	rule := SRSRule{}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if isIP {
			rule.IPCIDR = append(rule.IPCIDR, line)
		} else {
			if strings.HasPrefix(line, "full:") {
				rule.Domain = append(rule.Domain, strings.TrimPrefix(line, "full:"))
			} else if strings.HasPrefix(line, "regexp:") {
				rule.DomainRegex = append(rule.DomainRegex, strings.TrimPrefix(line, "regexp:"))
			} else if strings.HasPrefix(line, "keyword:") {
				rule.DomainKeyword = append(rule.DomainKeyword, strings.TrimPrefix(line, "keyword:"))
			} else {
				rule.DomainSuffix = append(rule.DomainSuffix, line)
			}
		}
	}
	f.Close()

	srsData := SRS{Version: 1, Rules: []SRSRule{rule}}
	jsonFile, srsFile := "../release/"+tag+".json", "../release/"+tag+".srs"
	if isIP {
		jsonFile, srsFile = "../release/"+tag+"-ip.json", "../release/"+tag+"-ip.srs"
	}

	b, _ := json.MarshalIndent(srsData, "", "  ")
	os.WriteFile(jsonFile, b, 0644)

	cmd := exec.Command("sing-box", "rule-set", "compile", jsonFile, "-o", srsFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()

	os.Remove(jsonFile)
}
