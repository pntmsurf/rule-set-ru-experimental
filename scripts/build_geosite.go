package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/v2fly/v2ray-core/v4/app/router"
	"google.golang.org/protobuf/proto"
)

func main() {
	var list router.GeoSiteList
	files, _ := filepath.Glob("../src/domains/*.txt")

	for _, file := range files {
		tag := strings.TrimSuffix(filepath.Base(file), ".txt")
		geosite := &router.GeoSite{CountryCode: strings.ToUpper(tag)}

		f, _ := os.Open(file)
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			domainType := router.Domain_Domain
			if strings.HasPrefix(line, "full:") {
				domainType = router.Domain_Full
				line = strings.TrimPrefix(line, "full:")
			} else if strings.HasPrefix(line, "regexp:") {
				domainType = router.Domain_Regex
				line = strings.TrimPrefix(line, "regexp:")
			} else if strings.HasPrefix(line, "keyword:") {
				domainType = router.Domain_Plain
				line = strings.TrimPrefix(line, "keyword:")
			}

			geosite.Domain = append(geosite.Domain, &router.Domain{
				Type:  domainType,
				Value: line,
			})
		}
		f.Close()
		list.Entry = append(list.Entry, geosite)
	}

	data, _ := proto.Marshal(&list)
	os.WriteFile("../release/geosite.dat", data, 0644)
}
