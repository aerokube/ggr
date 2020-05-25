package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"sync"
	"testing"

	. "github.com/aandryashin/matchers"
	. "github.com/aerokube/ggr/config"
)

func init() {
	verbose = true
}

func newIntPointer(i int) *int {
	return &i
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
	hosts, version, _ := browsersWithMultipleVersions.find("browser", "1.0", "LINUX", newSet(), newSet())
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

func TestFindWithAnyPlatform(t *testing.T) {
	hosts, version, _ := browsersWithMultiplePlatforms.find("browser", "2.0", "ANY", newSet(), newSet())
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
	testParseConfig(t, `<qa:browsers xmlns:qa="urn:config.gridrouter.qatools.ru"><browser name="browser"/></qa:browsers>`)
}

func TestParseConfigWithoutNamespace(t *testing.T) {
	testParseConfig(t, `<browsers><browser name="browser"/></browsers>`)
}

func testParseConfig(t *testing.T, config string) {
	tmp, err := ioutil.TempFile("", "config")
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

func TestFindMostFreeHostCapacity(t *testing.T) {
	var capacity = map[*Host]*capacity{
		&Host{Name: "MaxLoad", Count: 1}: {Queued: newIntPointer(10), Pending: newIntPointer(0), Used: newIntPointer(0), Total: newIntPointer(1)},
		&Host{Name: "MidLoad", Count: 1}: {Queued: newIntPointer(5), Pending: newIntPointer(0), Used: newIntPointer(0), Total: newIntPointer(1)},
		&Host{Name: "Free", Count: 1}:    {Queued: newIntPointer(0), Pending: newIntPointer(0), Used: newIntPointer(0), Total: newIntPointer(1)},
	}
	targetHost := mostFreeHost(capacity)
	AssertThat(t, targetHost, EqualTo{V: &Host{Name: "Free", Count: 1}})
}

func TestHostCapacity(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		switch req.RequestURI {
		case "/status":
			res.WriteHeader(200)
			res.Write([]byte(fmt.Sprintf("{\"Queued\":%s, \"Pending\":%d, \"Used\":%d, \"Total\":%d }", strconv.Itoa(rand.Intn(20)), 0, 0, 0)))
		}
	}))

	ip, _ := url.Parse(testServer.URL)
	port, _ := strconv.Atoi(ip.Port())

	hosts := Hosts{Host{Name: ip.Hostname(), Port: port, Count: 1}, Host{Name: "mid", Count: 1}, Host{Name: "last", Count: 1}}
	defer testServer.Close()
	target, _ := findFirstNodeByQueue(&hosts, &sync.RWMutex{})
	AssertThat(t, target, EqualTo{V: &hosts[0]})
}

func TestErrorResponseHostCapacity(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		switch req.RequestURI {
		case "/status":
			res.WriteHeader(500)
		}
	}))

	ip, _ := url.Parse(testServer.URL)
	port, _ := strconv.Atoi(ip.Port())

	hosts := Hosts{Host{Name: ip.Hostname(), Port: port, Count: 1}, Host{Name: "mid", Count: 1}, Host{Name: "last", Count: 1}}
	defer testServer.Close()
	_, err := findFirstNodeByQueue(&hosts, &sync.RWMutex{})
	AssertThat(t, err, Not{})
	AssertThat(t, err, EqualTo{V: errors.New("no valid host found")})
}

func TestEmptyHostListCapacity(t *testing.T) {
	currentHost := Host{Name: "", Port: 0, Count: 1}
	hosts := Hosts{}
	hosts = append(hosts, currentHost)
	target, _ := findFirstNodeByQueue(&hosts, &sync.RWMutex{})
	AssertThat(t, target, EqualTo{V: &currentHost})
}

func TestWrongHostResponse(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		switch req.RequestURI {
		case "/status":
			res.WriteHeader(200)
			res.Write([]byte(fmt.Sprintf("{\"Queued\":%s, \"Pending\":%d, \"Used\":%d}", strconv.Itoa(rand.Intn(20)), 0, 0)))
		}
	}))

	ip, _ := url.Parse(testServer.URL)
	port, _ := strconv.Atoi(ip.Port())
	hosts := Hosts{Host{Name: ip.Hostname(), Port: port, Count: 1}, Host{Name: "mid", Count: 1}, Host{Name: "last", Count: 1}}
	defer testServer.Close()
	_, err := findFirstNodeByQueue(&hosts, &sync.RWMutex{})
	AssertThat(t, err, Not{V: nil})
}

func TestPartialHostResponse(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		switch req.RequestURI {
		case "/status":
			res.WriteHeader(200)
			res.Write([]byte(fmt.Sprintf("{\"Queued\":%d, \"Pending\":%d, \"Used\":%d}", 2, 0, 0)))
		}
	}))

	testServer2 := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		switch req.RequestURI {
		case "/status":
			res.WriteHeader(200)
			res.Write([]byte(fmt.Sprintf("{\"Queued\":%d, \"Pending\":%d, \"Used\":%d, \"Total\":%d}", 3, 0, 0, 0)))
		}
	}))

	testServer3 := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		switch req.RequestURI {
		case "/status":
			res.WriteHeader(200)
			res.Write([]byte(fmt.Sprintf("{\"Queued\":%s, \"Used\":%d, \"Total\":%d}", strconv.Itoa(rand.Intn(20)), 0, 0)))
		}
	}))

	testServer4 := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		switch req.RequestURI {
		case "/status":
			res.WriteHeader(200)
			res.Write([]byte(fmt.Sprintf("{\"Pending\":%d, \"Used\":%d, \"Total\":%d}", 0, 0, 0)))
		}
	}))

	firstIp, _ := url.Parse(testServer.URL)
	firstPort, _ := strconv.Atoi(firstIp.Port())

	secondIp, _ := url.Parse(testServer2.URL)
	secondPort, _ := strconv.Atoi(secondIp.Port())

	thirdIp, _ := url.Parse(testServer3.URL)
	thirdPort, _ := strconv.Atoi(thirdIp.Port())

	fourthIp, _ := url.Parse(testServer4.URL)
	fourthPort, _ := strconv.Atoi(fourthIp.Port())

	hosts := Hosts{Host{Name: firstIp.Hostname(), Port: firstPort, Count: 1},
		Host{Name: secondIp.Hostname(), Port: secondPort, Count: 1},
		Host{Name: thirdIp.Hostname(), Port: thirdPort, Count: 1},
		Host{Name: fourthIp.Hostname(), Port: fourthPort, Count: 1},
		Host{Name: "last", Count: 1}}
	defer testServer.Close()
	defer testServer2.Close()
	defer testServer3.Close()
	defer testServer4.Close()
	target, _ := findFirstNodeByQueue(&hosts, &sync.RWMutex{})
	AssertThat(t, *target, EqualTo{V: hosts[1]})
}
