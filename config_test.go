package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"testing"

	"time"

	. "github.com/aandryashin/matchers"
	"github.com/fsnotify/fsnotify"
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

func TestReadUnexistentConfig(t *testing.T) {
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
	tmp, _ := ioutil.TempFile("", "config")
	os.Remove(tmp.Name())

	watcher, _ := fsnotify.NewWatcher()
	err := watchDir(watcher, tmp.Name(), 1*time.Millisecond)

	AssertThat(t, err, Is{Not{nil}})

	AssertThat(t, strings.HasPrefix(err.Error(), fmt.Sprintf("cannot watch directory: %s:", tmp.Name())), Is{true})
	AssertThat(t, strings.HasSuffix(err.Error(), fmt.Sprintf("%s: no such file or directory", tmp.Name())), Is{true})
}

func TestReloadConfig(t *testing.T) {
	tmp, _ := ioutil.TempFile("", "config")
	defer os.Remove(tmp.Name())

	test.Lock()
	defer test.Unlock()
	watcher, _ := fsnotify.NewWatcher()
	conf = tmp.Name()
	watchDir(watcher, path.Dir(tmp.Name()), 5*time.Millisecond)

	tmp.Write([]byte(`<qa:browsers xmlns:qa="urn:config.gridrouter.qatools.ru"><browser name="browser"/></qa:browsers>`))
	tmp.Close()

	<-time.After(100 * time.Millisecond)

	confLock.RLock()
	AssertThat(t, config.Browsers[0].Name, EqualTo{"browser"})
	confLock.RUnlock()

	os.Remove(tmp.Name())
	<-time.After(100 * time.Millisecond)

	AssertThat(t, config.Browsers[0].Name, EqualTo{"browser"})
}