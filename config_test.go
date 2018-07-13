package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	. "github.com/aandryashin/matchers"
	. "github.com/aerokube/ggr/config"
)

func init() {
	verbose = true
}

func TestEmptyListOfHosts(t *testing.T) {
	host, index := choose(Hosts{})
	AssertThat(t, host, Is{(*Host)(nil)})
	AssertThat(t, index, EqualTo{-1})
}

func TestNothingToChoose(t *testing.T) {
	host, index := choose(Hosts{Host{Count: 0}, Host{Count: 0}})
	AssertThat(t, host, Is{(*Host)(nil)})
	AssertThat(t, index, EqualTo{-1})
}

func TestChooseFirst(t *testing.T) {
	host, index := choose(Hosts{Host{Name: "first", Count: 1}, Host{Name: "mid", Count: 0}, Host{Name: "last", Count: 0}})
	AssertThat(t, host.Name, EqualTo{"first"})
	AssertThat(t, index, EqualTo{0})
}

func TestChooseMid(t *testing.T) {
	host, index := choose(Hosts{Host{Name: "first", Count: 0}, Host{Name: "mid", Count: 1}, Host{Name: "last", Count: 0}})
	AssertThat(t, host.Name, EqualTo{"mid"})
	AssertThat(t, index, EqualTo{1})
}

func TestChooseLast(t *testing.T) {
	host, index := choose(Hosts{Host{Name: "first", Count: 0}, Host{Name: "mid", Count: 0}, Host{Name: "last", Count: 1}})
	AssertThat(t, host.Name, EqualTo{"last"})
	AssertThat(t, index, EqualTo{2})
}

var (
	browsersWithMultipleVersions = &ggrBrowsers{Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "2.0", Versions: []Version{
			{Number: "2.0", Regions: []Region{
				{Hosts: Hosts{
					Host{Name: "browser-2.0"},
				}},
			}},
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					Host{Name: "browser-1.0"},
				}},
			}},
			{Number: "", Regions: []Region{
				{Hosts: Hosts{
					Host{Name: "browser"},
				}},
			}},
		}}}}}

	browsersWithMultipleRegions = &ggrBrowsers{Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Name: "e", Hosts: Hosts{
					Host{Name: "browser-e-1.0", Port: 4444},
				}},
				{Name: "f", Hosts: Hosts{
					Host{Name: "browser-f-1.0", Port: 4444},
				}},
			}},
		}}}}}

	browsersWithMultiplePlatforms = &ggrBrowsers{Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "2.0", DefaultPlatform: "LINUX", Versions: []Version{
			{Number: "2.0", Platform: "LINUX", Regions: []Region{
				{Hosts: Hosts{
					Host{Name: "browser-2.0-linux"},
				}},
			}},
			{Number: "2.0", Platform: "WINDOWS", Regions: []Region{
				{Hosts: Hosts{
					Host{Name: "browser-2.0-windows"},
				}},
			}},
		}}}}}
)

func TestFindDefaultVersion(t *testing.T) {
	hosts, version, _ := browsersWithMultipleVersions.find("browser", "", "", newSet(), newSet())
	AssertThat(t, version, EqualTo{"2.0"})
	AssertThat(t, len(hosts), EqualTo{1})
	AssertThat(t, hosts[0].Name, EqualTo{"browser-2.0"})
}

func TestFindVersion(t *testing.T) {
	hosts, version, _ := browsersWithMultipleVersions.find("browser", "1.0", "", newSet(), newSet())
	AssertThat(t, version, EqualTo{"1.0"})
	AssertThat(t, len(hosts), EqualTo{1})
	AssertThat(t, hosts[0].Name, EqualTo{"browser-1.0"})
}

func TestFindVersionByPrefix(t *testing.T) {
	hosts, version, _ := browsersWithMultipleVersions.find("browser", "1", "", newSet(), newSet())
	AssertThat(t, version, EqualTo{"1.0"})
	AssertThat(t, len(hosts), EqualTo{1})
	AssertThat(t, hosts[0].Name, EqualTo{"browser-1.0"})
}

func TestVersionNotFound(t *testing.T) {
	hosts, version, _ := browsersWithMultipleVersions.find("browser", "missing", "", newSet(), newSet())
	AssertThat(t, version, EqualTo{"missing"})
	AssertThat(t, len(hosts), EqualTo{0})
}

func TestFindWithExcludedRegions(t *testing.T) {
	hosts, version, _ := browsersWithMultipleRegions.find("browser", "1.0", "", newSet(), newSet("f"))
	AssertThat(t, version, EqualTo{"1.0"})
	AssertThat(t, len(hosts), EqualTo{1})
	AssertThat(t, hosts[0].Name, EqualTo{"browser-e-1.0"})
}

func TestFindWithExcludedRegionsExhausted(t *testing.T) {
	hosts, _, excludedRegions := browsersWithMultipleRegions.find("browser", "1.0", "", newSet(), newSet("e", "f"))
	AssertThat(t, len(hosts), EqualTo{2})
	AssertThat(t, excludedRegions.size(), EqualTo{0})
}

func TestFindWithExcludedHosts(t *testing.T) {
	hosts, version, _ := browsersWithMultipleRegions.find("browser", "1.0", "", newSet("browser-e-1.0:4444"), newSet())
	AssertThat(t, version, EqualTo{"1.0"})
	AssertThat(t, len(hosts), EqualTo{1})
	AssertThat(t, hosts[0].Name, EqualTo{"browser-f-1.0"})
}

func TestFindWithDefaultPlatform(t *testing.T) {
	hosts, version, _ := browsersWithMultiplePlatforms.find("browser", "2.0", "", newSet(), newSet())
	AssertThat(t, version, EqualTo{"2.0"})
	AssertThat(t, len(hosts), EqualTo{1})
	AssertThat(t, hosts[0].Name, EqualTo{"browser-2.0-linux"})
}

func TestFindWithPlatform(t *testing.T) {
	hosts, version, _ := browsersWithMultiplePlatforms.find("browser", "2.0", "LINUX", newSet(), newSet())
	AssertThat(t, version, EqualTo{"2.0"})
	AssertThat(t, len(hosts), EqualTo{1})
	AssertThat(t, hosts[0].Name, EqualTo{"browser-2.0-linux"})
}

func TestFindWithPlatformPrefix(t *testing.T) {
	hosts, version, _ := browsersWithMultiplePlatforms.find("browser", "2.0", "WIN", newSet(), newSet())
	AssertThat(t, version, EqualTo{"2.0"})
	AssertThat(t, len(hosts), EqualTo{1})
	AssertThat(t, hosts[0].Name, EqualTo{"browser-2.0-windows"})
}

func TestReadNotExistingConfig(t *testing.T) {
	tmp, err := ioutil.TempFile("", "config")
	if err != nil {
		t.Fatal(err)
	}
	err = os.Remove(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	var browsers Browsers
	err = readConfig(tmp.Name(), &browsers)

	AssertThat(t, err, Is{Not{nil}})
	AssertThat(t, err.Error(), EqualTo{fmt.Sprintf("error reading configuration file %s: open %s: no such file or directory", tmp.Name(), tmp.Name())})
}

func TestParseInvalidConfig(t *testing.T) {
	tmp, err := ioutil.TempFile("", "config")
	defer os.Remove(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	_, err = tmp.Write([]byte("this is not valid xml"))
	if err != nil {
		t.Fatal(err)
	}
	err = tmp.Close()
	if err != nil {
		t.Fatal(err)
	}
	var browsers Browsers
	err = readConfig(tmp.Name(), &browsers)

	AssertThat(t, err, Is{Not{nil}})
	AssertThat(t, err.Error(), EqualTo{fmt.Sprintf("error parsing configuration file %s: EOF", tmp.Name())})
}

func TestParseConfig(t *testing.T) {
	tmp, err := ioutil.TempFile("", "config")
	defer os.Remove(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	_, err = tmp.Write([]byte(`<qa:browsers xmlns:qa="urn:config.gridrouter.qatools.ru"><browser name="browser"/></qa:browsers>`))
	if err != nil {
		t.Fatal(err)
	}
	err = tmp.Close()
	if err != nil {
		t.Fatal(err)
	}
	var browsers Browsers
	err = readConfig(tmp.Name(), &browsers)

	AssertThat(t, err, Is{nil})
	AssertThat(t, browsers.Browsers[0].Name, EqualTo{"browser"})
}

func TestConfDirDoesNotExist(t *testing.T) {
	err := loadQuotaFiles("missing-dir")
	AssertThat(t, err, Is{Not{nil}})
}

func TestConcurrentReload(t *testing.T) {
	go func() {
		loadQuotaFiles("quota")
	}()
	loadQuotaFiles("quota")
}

func TestChoosingAllHosts(t *testing.T) {
	//NOTE: the same weights for all hosts are important!
	hosts := Hosts{Host{Name: "first", Count: 1}, Host{Name: "mid", Count: 1}, Host{Name: "last", Count: 1}}
	chosenHosts := make(map[string]int)
	for i := 0; i < 100; i++ {
		host, _ := choose(hosts)
		chosenHosts[host.Name]++
	}
	AssertThat(t, chosenHosts["first"] > 0, Is{true})
	AssertThat(t, chosenHosts["mid"] > 0, Is{true})
	AssertThat(t, chosenHosts["last"] > 0, Is{true})
}
