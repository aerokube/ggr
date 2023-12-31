package main

import (
	"fmt"
	assert "github.com/stretchr/testify/require"
	"os"
	"testing"

	. "github.com/aerokube/ggr/config"
)

func init() {
	verbose = true
}

func TestEmptyListOfHosts(t *testing.T) {
	host, index := choose(Hosts{})
	assert.Nil(t, host)
	assert.Equal(t, index, -1)
}

func TestNothingToChoose(t *testing.T) {
	host, index := choose(Hosts{Host{Count: 0}, Host{Count: 0}})
	assert.Nil(t, host)
	assert.Equal(t, index, -1)
}

func TestChooseFirst(t *testing.T) {
	host, index := choose(Hosts{Host{Name: "first", Count: 1}, Host{Name: "mid", Count: 0}, Host{Name: "last", Count: 0}})
	assert.Equal(t, host.Name, "first")
	assert.Equal(t, index, 0)
}

func TestChooseMid(t *testing.T) {
	host, index := choose(Hosts{Host{Name: "first", Count: 0}, Host{Name: "mid", Count: 1}, Host{Name: "last", Count: 0}})
	assert.Equal(t, host.Name, "mid")
	assert.Equal(t, index, 1)
}

func TestChooseLast(t *testing.T) {
	host, index := choose(Hosts{Host{Name: "first", Count: 0}, Host{Name: "mid", Count: 0}, Host{Name: "last", Count: 1}})
	assert.Equal(t, host.Name, "last")
	assert.Equal(t, index, 2)
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
	assert.Equal(t, version, "2.0")
	assert.Len(t, hosts, 1)
	assert.Equal(t, hosts[0].Name, "browser-2.0")
}

func TestFindVersion(t *testing.T) {
	hosts, version, _ := browsersWithMultipleVersions.find("browser", "1.0", "LINUX", newSet(), newSet())
	assert.Equal(t, version, "1.0")
	assert.Len(t, hosts, 1)
	assert.Equal(t, hosts[0].Name, "browser-1.0")
}

func TestFindVersionByPrefix(t *testing.T) {
	hosts, version, _ := browsersWithMultipleVersions.find("browser", "1", "", newSet(), newSet())
	assert.Equal(t, version, "1.0")
	assert.Len(t, hosts, 1)
	assert.Equal(t, hosts[0].Name, "browser-1.0")
}

func TestVersionNotFound(t *testing.T) {
	hosts, version, _ := browsersWithMultipleVersions.find("browser", "missing", "", newSet(), newSet())
	assert.Equal(t, version, "missing")
	assert.Empty(t, hosts)
}

func TestFindWithExcludedRegions(t *testing.T) {
	hosts, version, _ := browsersWithMultipleRegions.find("browser", "1.0", "", newSet(), newSet("f"))
	assert.Equal(t, version, "1.0")
	assert.Len(t, hosts, 1)
	assert.Equal(t, hosts[0].Name, "browser-e-1.0")
}

func TestFindWithExcludedRegionsExhausted(t *testing.T) {
	hosts, _, excludedRegions := browsersWithMultipleRegions.find("browser", "1.0", "", newSet(), newSet("e", "f"))
	assert.Len(t, hosts, 2)
	assert.Equal(t, excludedRegions.size(), 0)
}

func TestFindWithExcludedHosts(t *testing.T) {
	hosts, version, _ := browsersWithMultipleRegions.find("browser", "1.0", "", newSet("browser-e-1.0:4444"), newSet())
	assert.Equal(t, version, "1.0")
	assert.Len(t, hosts, 1)
	assert.Equal(t, hosts[0].Name, "browser-f-1.0")
}

func TestFindWithDefaultPlatform(t *testing.T) {
	hosts, version, _ := browsersWithMultiplePlatforms.find("browser", "2.0", "", newSet(), newSet())
	assert.Equal(t, version, "2.0")
	assert.Len(t, hosts, 1)
	assert.Equal(t, hosts[0].Name, "browser-2.0-linux")
}

func TestFindWithAnyPlatform(t *testing.T) {
	hosts, version, _ := browsersWithMultiplePlatforms.find("browser", "2.0", "ANY", newSet(), newSet())
	assert.Equal(t, version, "2.0")
	assert.Len(t, hosts, 1)
	assert.Equal(t, hosts[0].Name, "browser-2.0-linux")
}

func TestFindWithPlatform(t *testing.T) {
	hosts, version, _ := browsersWithMultiplePlatforms.find("browser", "2.0", "LINUX", newSet(), newSet())
	assert.Equal(t, version, "2.0")
	assert.Len(t, hosts, 1)
	assert.Equal(t, hosts[0].Name, "browser-2.0-linux")
}

func TestFindWithPlatformLowercase(t *testing.T) {
	hosts, version, _ := browsersWithMultiplePlatforms.find("browser", "2.0", "windows", newSet(), newSet())
	assert.Equal(t, version, "2.0")
	assert.Len(t, hosts, 1)
	assert.Equal(t, hosts[0].Name, "browser-2.0-windows")
}

func TestFindWithPlatformPrefix(t *testing.T) {
	hosts, version, _ := browsersWithMultiplePlatforms.find("browser", "2.0", "WIN", newSet(), newSet())
	assert.Equal(t, version, "2.0")
	assert.Len(t, hosts, 1)
	assert.Equal(t, hosts[0].Name, "browser-2.0-windows")
}

func TestReadNotExistingConfig(t *testing.T) {
	tmp, err := os.CreateTemp("", "config")
	if err != nil {
		t.Fatal(err)
	}
	err = os.Remove(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	var browsers Browsers
	err = readConfig(tmp.Name(), &browsers)

	assert.Error(t, err)
	assert.Equal(t, err.Error(), fmt.Sprintf("error reading configuration file %s: open %s: no such file or directory", tmp.Name(), tmp.Name()))
}

func TestParseInvalidConfig(t *testing.T) {
	tmp, err := os.CreateTemp("", "config")
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

	assert.Error(t, err)
	assert.Equal(t, err.Error(), fmt.Sprintf("error parsing configuration file %s: EOF", tmp.Name()))
}

func TestParseConfig(t *testing.T) {
	testParseConfig(t, `<qa:browsers xmlns:qa="urn:config.gridrouter.qatools.ru"><browser name="browser"/></qa:browsers>`)
}

func TestParseConfigWithoutNamespace(t *testing.T) {
	testParseConfig(t, `<browsers><browser name="browser"/></browsers>`)
}

func testParseConfig(t *testing.T, config string) {
	tmp, err := os.CreateTemp("", "config")
	defer os.Remove(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	_, err = tmp.Write([]byte(config))
	if err != nil {
		t.Fatal(err)
	}
	err = tmp.Close()
	if err != nil {
		t.Fatal(err)
	}
	var browsers Browsers
	err = readConfig(tmp.Name(), &browsers)

	assert.NoError(t, err)
	assert.Equal(t, browsers.Browsers[0].Name, "browser")
}

func TestConfDirDoesNotExist(t *testing.T) {
	err := loadQuotaFiles("missing-dir")
	assert.Error(t, err)
}

func TestConcurrentReload(t *testing.T) {
	go func() {
		_ = loadQuotaFiles("quota")
	}()
	_ = loadQuotaFiles("quota")
}

func TestChoosingAllHosts(t *testing.T) {
	//NOTE: the same weights for all hosts are important!
	hosts := Hosts{Host{Name: "first", Count: 1}, Host{Name: "mid", Count: 1}, Host{Name: "last", Count: 1}}
	chosenHosts := make(map[string]int)
	for i := 0; i < 100; i++ {
		host, _ := choose(hosts)
		chosenHosts[host.Name]++
	}
	assert.True(t, chosenHosts["first"] > 0)
	assert.True(t, chosenHosts["mid"] > 0)
	assert.True(t, chosenHosts["last"] > 0)
}
