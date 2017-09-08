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
	Name     string `xml:"name,attr"`
	Port     int    `xml:"port,attr"`
	Count    int    `xml:"count,attr"`
	Username string `xml:"username,attr,omitempty"`
	Password string `xml:"password,attr,omitempty"`
	region   string
}
type set interface {
	contains(el string) bool
	add(el string)
	size() int
}

func newSet(data ...string) *setImpl {
	set := &setImpl{make(map[string]struct{})}
	for _, el := range data {
		set.add(el)
	}
	return set
}

type setImpl struct {
	data map[string]struct{}
}

func (ss *setImpl) contains(el string) bool {
	_, ok := ss.data[el]
	return ok
}

func (ss *setImpl) add(el string) {
	ss.data[el] = struct{}{}
}

func (ss *setImpl) size() int {
	return len(ss.data)
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

func (b *Browsers) find(browser, version string, excludedHosts set, excludedRegions set) (Hosts, string, set) {
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
						if excludedRegions.size() == len(v.Regions) {
							excludedRegions = newSet()
						}
						if excludedRegions.contains(r.Name) {
							continue next
						}
						for _, h := range r.Hosts {
							if !excludedHosts.contains(h.net()) {
								hosts = append(hosts, h)
							}
						}
					}
				}
			}
		}
	}
	return hosts, version, excludedRegions
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
			if r < 0 {
				return &hosts[i], i
			}
		}
	}
	return nil, -1
}
