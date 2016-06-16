package main

import (
	"testing"

	. "github.com/aandryashin/matchers"
)

func TestEmptyListOfHosts(t *testing.T) {
	host, index := Hosts{}.choose()
	AssertThat(t, host, Is{(*Host)(nil)})
	AssertThat(t, index, EqualTo{-1})
}

func TestNothingToChoose(t *testing.T) {
	host, index := Hosts{Host{Count: 0}, Host{Count: 0}}.choose()
	AssertThat(t, host, Is{(*Host)(nil)})
	AssertThat(t, index, EqualTo{-1})
}

func TestChooseFirst(t *testing.T) {
	host, index := Hosts{Host{Name: "first", Count: 2}, Host{Name: "mid", Count: 1}, Host{Name: "last", Count: 1}}.choose()
	AssertThat(t, host.Name, EqualTo{"first"})
	AssertThat(t, index, EqualTo{0})
}

func TestChooseMid(t *testing.T) {
	host, index := Hosts{Host{Name: "first", Count: 1}, Host{Name: "mid", Count: 2}, Host{Name: "last", Count: 1}}.choose()
	AssertThat(t, host.Name, EqualTo{"mid"})
	AssertThat(t, index, EqualTo{1})
}

func TestChooseLast(t *testing.T) {
	host, index := Hosts{Host{Name: "first", Count: 1}, Host{Name: "mid", Count: 1}, Host{Name: "last", Count: 2}}.choose()
	AssertThat(t, host.Name, EqualTo{"last"})
	AssertThat(t, index, EqualTo{2})
}
