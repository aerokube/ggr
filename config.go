package main

import (
	. "github.com/aerokube/ggr/config"
	"math/rand"
	"strings"
)

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

func sessionURL(h *Host) string {
	return h.Route() + routePath
}

type ggrBrowsers struct {
	Browsers
}

func (b *ggrBrowsers) find(browser, version string, excludedHosts set, excludedRegions set) (Hosts, string, set) {
	var hosts Hosts
	for _, b := range b.Browsers.Browsers {
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
							if !excludedHosts.contains(h.Net()) {
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

func choose(hosts Hosts) (*Host, int) {
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
