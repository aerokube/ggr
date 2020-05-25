package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	. "github.com/aerokube/ggr/config"
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
	Queued  *int `json:"queued,omitempty" binding:"required"`
	Pending *int `json:"pending,omitempty" binding:"required"`
	Used    *int `json:"used,omitempty" binding:"required"`
	Total   *int `json:"total,omitempty" binding:"required"`
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

func findFirstNodeByQueue(hosts *Hosts, mutex *sync.RWMutex) (host *Host, err error) {
	if len(*hosts) == 1 {
		return &(*hosts)[0], nil
	}
	hostMap := map[string]*Host{}
	for i, v := range *hosts {
		hostMap[fmt.Sprintf("%s%d%s", v.Name, v.Port, v.Region)] = &(*hosts)[i]
	}
	mutex.Lock()
	resultMap := make(map[*Host]*capacity)
	defer mutex.Unlock()
	var netClient = &http.Client{
		Timeout: time.Second * 10,
	}
	for i := 0; i < len(*hosts); i++ {
		rsp, err := netClient.Get((*hosts)[i].StatusEndPoint())
		if err != nil {
			continue
		}
		var capa capacity
		decoder := json.NewDecoder(rsp.Body)
		decoder.DisallowUnknownFields()
		err = decoder.Decode(&capa)
		if err != nil && i < len(*hosts) {
			continue
		}
		if capa.Pending == nil || capa.Queued == nil || capa.Total == nil || capa.Used == nil {
			continue
		}
		resultMap[&(*hosts)[i]] = &capa
	}
	netClient.CloseIdleConnections()
	if len(resultMap) < 1 {
		return nil, errors.New("no valid host found")
	}
	var target = mostFreeHost(resultMap)
	if v, ok := hostMap[fmt.Sprintf("%s%d%s", target.Name, target.Port, target.Region)]; ok {
		return v, nil
	}
	return nil, errors.New("no valid host found")

}

func mostFreeHost(target map[*Host]*capacity) *Host {
	var queued int
	var targetHost *Host
	i := len(target)
	for k, v := range target {
		if i == len(target) {
			queued = *v.Queued
			targetHost = k
		}
		if *v.Queued < queued {
			queued = *v.Queued
			targetHost = k
		}
		i--
	}
	return targetHost
}
