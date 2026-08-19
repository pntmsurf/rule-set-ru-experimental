package main

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/v2fly/v2ray-core/v4/app/router"
	"google.golang.org/protobuf/proto"
)

func main() {
	var list router.GeoIPList
	files, _ := filepath.Glob("../src/ips/*.txt")

	for _, file := range files {
		tag := strings.TrimSuffix(filepath.Base(file), ".txt")
		geoip := &router.GeoIP{CountryCode: strings.ToUpper(tag)}

		f, _ := os.Open(file)
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			ip, ipnet, err := net.ParseCIDR(line)
			if err != nil {
				ip = net.ParseIP(line)
				if ip == nil {
					continue
				}
				if ip.To4() != nil {
					ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
				} else {
					ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
				}
			}

			ones, _ := ipnet.Mask.Size()
			ipBytes := ip.To4()
			if ipBytes == nil {
				ipBytes = ip.To16()
			}

			geoip.Cidr = append(geoip.Cidr, &router.CIDR{
				Ip:     ipBytes,
				Prefix: uint32(ones),
			})
		}
		f.Close()
		list.Entry = append(list.Entry, geoip)
	}

	data, _ := proto.Marshal(&list)
	os.WriteFile("../release/geoip.dat", data, 0644)
}
