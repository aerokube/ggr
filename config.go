package main

import (
	"encoding/json"
	"fmt"
	. "github.com/aerokube/ggr/config"
	"io/ioutil"
	"math/rand"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
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

type capacity struct {
	Key     *Host
	queued  int
	pending int
	used    int
	total   int
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
	return h.Route() + paths.Route
}

type ggrBrowsers struct {
	Browsers
}

const anyPlatform = "ANY"

func (b *ggrBrowsers) find(browser, version string, platform string, excludedHosts set, excludedRegions set) (Hosts, string, set) {
	var hosts Hosts
	for _, b := range b.Browsers.Browsers {
		if b.Name == browser {
			if version == "" {
				version = b.DefaultVersion
			}
			if platform == "" || platform == anyPlatform {
				platform = b.DefaultPlatform
			}
			for _, v := range b.Versions {
				if strings.HasPrefix(v.Number, version) && (v.Platform == "" || strings.HasPrefix(v.Platform, platform)) {
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

func findFirstNodeByQueue(currentHost *Host, hosts *Hosts, mutex *sync.RWMutex) (host *Host) {
	if len(*hosts) < 1 {
		return currentHost
	}
	hostMap := map[string]*Host{}
	for v := range *hosts {
		hostMap[fmt.Sprintf("%s%d%s", (*hosts)[v].Name, (*hosts)[v].Port, (*hosts)[v].Region)] = &(*hosts)[v]
	}
	var capacities []capacity
	mutex.Lock()
	defer mutex.Unlock()
	var netClient = &http.Client{
		Timeout: time.Second * 10,
	}
	for i := range *hosts {
		rsp, err := netClient.Get((*hosts)[i].StatusEndPoint())
		if err != nil {
			continue
		}

		responseMap := make(map[string]interface{})
		body, err := ioutil.ReadAll(rsp.Body)
		if err != nil {
			return currentHost
		}

		err = json.Unmarshal(body, &responseMap)
		if err != nil {
			return currentHost
		}
		var cap capacity
		if queued, ok := responseMap["queued"]; ok {
			cap.queued = int(queued.(float64))
		} else {
			continue
		}

		if pending, ok := responseMap["pending"]; ok {
			cap.pending = int(pending.(float64))
		} else {
			continue
		}

		if used, ok := responseMap["used"]; ok {
			cap.used = int(used.(float64))
		} else {
			continue
		}

		if total, ok := responseMap["total"]; ok {
			cap.total = int(total.(float64))
		} else {
			continue
		}

		cap.Key = &(*hosts)[i]
		capacities = append(capacities, cap)
	}
	if len(capacities) < 1 {
		return currentHost
	}
	var target = mostFreeHost(capacities)
	if v, ok := hostMap[fmt.Sprintf("%s%d%s", target.Name, target.Port, target.Region)]; ok {
		if &v == &currentHost {
			return currentHost
		}
		return v
	}

	return currentHost
}

func mostFreeHost(values []capacity) *Host {
	sort.Slice(values, func(i, j int) bool {
		return values[i].queued < values[j].queued
	})
	return values[0].Key
}
