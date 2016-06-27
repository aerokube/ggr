package main

import (
	"crypto/md5"
	"encoding/xml"
	"fmt"
	"math/rand"
	"strings"
)

type Browsers struct {
	XMLName  xml.Name  `xml:"urn:config.gridrouter.qatools.ru browsers"`
	Browsers []Browser `xml:"browser"`
}

type Browser struct {
	Name           string    `xml:"name,attr"`
	DefaultVersion string    `xml:"defaultVersion,attr"`
	Versions       []Version `xml:"version"`
}

type Version struct {
	Number  string   `xml:"number,attr"`
	Regions []Region `xml:"region"`
}

type Hosts []Host

type Region struct {
	Name  string `xml:"name,attr"`
	Hosts Hosts  `xml:"host"`
}

type Host struct {
	Name   string `xml:"name,attr"`
	Port   int    `xml:"port,attr"`
	Count  int    `xml:"count,attr"`
	region string
}

func (h *Host) net() string {
	return fmt.Sprintf("%s:%d", h.Name, h.Port)
}

func (h *Host) sum() string {
	return fmt.Sprintf("%x", md5.Sum([]byte(h.net())))
}

func (browsers *Browsers) find(browser, version string, excludes ...string) (hosts Hosts) {
	for _, b := range browsers.Browsers {
		if b.Name == browser {
			if version == "" {
				version = b.DefaultVersion
			}
			for _, v := range b.Versions {
				if strings.HasPrefix(v.Number, version) {
				next:
					for _, r := range v.Regions {
						for _, e := range excludes {
							if r.Name == e {
								continue next
							}
						}
						hosts = append(hosts, r.Hosts...)
					}
				}
			}
		}
	}
	return hosts
}

func (hosts Hosts) choose() (*Host, int) {
	total := 0
	for _, h := range hosts {
		total += h.Count
	}
	if total > 0 {
		r := rand.Intn(total)
		for i, host := range hosts {
			r -= host.Count
			if r <= 0 {
				return &hosts[i], i
			}
		}
	}
	return nil, -1
}
