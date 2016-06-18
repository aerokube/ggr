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

func TestFindDefaultVersion(t *testing.T) {
	hosts := (&Browsers{Browsers: []Browser{
		Browser{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			Version{Number: "1.0", Regions: []Region{
				Region{Hosts: Hosts{
					Host{Name: "browser-1.0"},
				}},
			}},
			Version{Number: "", Regions: []Region{
				Region{Hosts: Hosts{
					Host{Name: "browser"},
				}},
			}},
		}}}}).find("browser", "")
	AssertThat(t, len(hosts), EqualTo{1})
	AssertThat(t, hosts[0].Name, EqualTo{"browser-1.0"})
}

func TestFindVersion(t *testing.T) {
	hosts := (&Browsers{Browsers: []Browser{
		Browser{Name: "browser", DefaultVersion: "2.0", Versions: []Version{
			Version{Number: "2.0", Regions: []Region{
				Region{Hosts: Hosts{
					Host{Name: "browser-2.0"},
				}},
			}},
			Version{Number: "1.0", Regions: []Region{
				Region{Hosts: Hosts{
					Host{Name: "browser-1.0"},
				}},
			}},
		}}}}).find("browser", "1.0")
	AssertThat(t, len(hosts), EqualTo{1})
	AssertThat(t, hosts[0].Name, EqualTo{"browser-1.0"})
}

func TestVersionNotFound(t *testing.T) {
	hosts := (&Browsers{Browsers: []Browser{
		Browser{Name: "browser", DefaultVersion: "2.0", Versions: []Version{
			Version{Number: "2.0", Regions: []Region{
				Region{Hosts: Hosts{
					Host{Name: "browser-2.0"},
				}},
			}},
		}}}}).find("browser", "1.0")
	AssertThat(t, len(hosts), EqualTo{0})
}

func TestFindWithExcludes(t *testing.T) {
	hosts := (&Browsers{Browsers: []Browser{
		Browser{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			Version{Number: "1.0", Regions: []Region{
				Region{Name: "e", Hosts: Hosts{
					Host{Name: "browser-e-1.0"},
				}},
				Region{Name: "f", Hosts: Hosts{
					Host{Name: "browser-f-1.0"},
				}},
			}},
		}}}}).find("browser", "1.0", "f")
	AssertThat(t, len(hosts), EqualTo{1})
	AssertThat(t, hosts[0].Name, EqualTo{"browser-e-1.0"})
}
