package config

import (
	"crypto/md5"
	"encoding/xml"
	"fmt"
)

// Browsers - a set of available browsers
type Browsers struct {
	XMLName  xml.Name  `xml:"browsers"`
	Browsers []Browser `xml:"browser"`
}

// Browser - one browser name, e.g. Firefox with all available versions
type Browser struct {
	Name            string    `xml:"name,attr"`
	DefaultVersion  string    `xml:"defaultVersion,attr"`
	DefaultPlatform string    `xml:"defaultPlatform,attr,omitempty"`
	Versions        []Version `xml:"version"`
}

// Version - concrete browser version
type Version struct {
	Number   string   `xml:"number,attr"`
	Platform string   `xml:"platform,attr"`
	Regions  []Region `xml:"region"`
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
	Name     string   `xml:"name,attr"`
	Port     int      `xml:"port,attr"`
	Count    int      `xml:"count,attr"`
	Username string   `xml:"username,attr,omitempty"`
	Password string   `xml:"password,attr,omitempty"`
	VNC      string   `xml:"vnc,attr,omitempty"`
	Scheme   string   `xml:"scheme,attr,omitempty"`
	Region   string   `xml:"-" json:"-"`
	VncInfo  *VncInfo `xml:"-" json:"-"`
}

func (h *Host) Net() string {
	return fmt.Sprintf("%s:%d", h.Name, h.Port)
}

func (h *Host) Route() string {
	scheme := h.Scheme
	if scheme == "" {
		scheme = "http"
	}
	return scheme + "://" + h.Net()
}

func (h *Host) Sum() string {
	return fmt.Sprintf("%x", md5.Sum([]byte(h.Route())))
}

// VncInfo - parsed VNC connection information
type VncInfo struct {
	Scheme string
	Host   string
	Port   string
	Path   string
}
