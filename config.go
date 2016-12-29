package main

import (
	"crypto/md5"
	"encoding/xml"
	"fmt"
	"math/rand"
	"strings"
)

// Browsers - a set of available browsers
type Browsers struct {
	XMLName  xml.Name  `xml:"urn:config.gridrouter.qatools.ru browsers"`
	Browsers []Browser `xml:"browser"`
}

// Browser - one browser name, e.g. Firefox with all available versions
type Browser struct {
	Name           string    `xml:"name,attr"`
	DefaultVersion string    `xml:"defaultVersion,attr"`
	Versions       []Version `xml:"version"`
}

// Version - concrete browser version
type Version struct {
	Number  string   `xml:"number,attr"`
	Regions []Region `xml:"region"`
}

// Hosts - a list of hosts for browser version
type Hosts []Host

// Region - a datacenter to group hosts
type Region struct {
	Name  string `xml:"name,attr"`
	Hosts Hosts  `xml:"host"`
}

// Host - just a hostname
type Host struct {
	Name   string `xml:"name,attr"`
	Port   int    `xml:"port,attr"`
	Count  int    `xml:"count,attr"`
	region string
}

func (b Browsers) String() string {
	buf, _ := xml.MarshalIndent(b, "", "  ")
	return string(buf)
}

func (h *Host) net() string {
	return fmt.Sprintf("%s:%d", h.Name, h.Port)
}

func (h *Host) route() string {
	return "http://" + h.net()
}

func (h *Host) sessionURL() string {
	return h.route() + routePath
}

func (h *Host) sum() string {
	return fmt.Sprintf("%x", md5.Sum([]byte(h.route())))
}

func (b *Browsers) find(browser, version string, excludes ...string) (Hosts, string) {
	var hosts Hosts
	for _, b := range b.Browsers {
		if b.Name == browser {
			if version == "" {
				version = b.DefaultVersion
			}
			for _, v := range b.Versions {
				if strings.HasPrefix(v.Number, version) {
					version = v.Number
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
	return hosts, version
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
