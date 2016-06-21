package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	. "github.com/aandryashin/matchers"
)

var (
	srv  *httptest.Server
	test sync.Mutex
)

type Code struct {
	C int
}

func (m Code) Match(i interface{}) bool {
	return i.(*http.Response).StatusCode == m.C
}

func (m Code) String() string {
	return fmt.Sprintf("response code %v", m.C)
}

type Body struct {
	B string
}

func (m Body) Match(i interface{}) bool {
	rsp := i.(*http.Response)
	body, _ := ioutil.ReadAll(rsp.Body)
	rsp.Body.Close()
	return EqualTo{m.B}.Match(strings.TrimSpace(string(body)))
}

func (m Body) String() string {
	return fmt.Sprintf("response body %v", m.B)
}

func hostport(u string) string {
	uri, _ := url.Parse(u)
	return uri.Host
}

func hostportnum(u string) (string, int) {
	host, portS, _ := net.SplitHostPort(hostport(u))
	port, _ := strconv.Atoi(portS)
	return host, port
}

func init() {
	srv = httptest.NewServer(mux())
	listen = hostport(srv.URL)
}

func gridrouter(p string) string {
	return fmt.Sprintf("%s%s", srv.URL, p)
}

func TestPing(t *testing.T) {
	rsp, err := http.Get(gridrouter("/ping"))

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusOK}, Body{"Ok"}})
}

func TestErr(t *testing.T) {
	rsp, err := http.Get(gridrouter("/err"))

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusNotFound}, Body{"route not found"}})
}

func TestCreateSessionGet(t *testing.T) {
	rsp, err := http.Get(gridrouter("/wd/hub/session"))

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusMethodNotAllowed}, Body{"method not allowed"}})
}

func TestCreateSessionEmptyBody(t *testing.T) {
	rsp, err := http.Post(gridrouter("/wd/hub/session"), "", nil)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusBadRequest}, Body{"bad json format: EOF"}})
}

func TestCreateSessionBadJson(t *testing.T) {
	rsp, err := http.Post(gridrouter("/wd/hub/session"), "", bytes.NewReader([]byte("")))

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusBadRequest}, Body{"bad json format: EOF"}})
}

func TestCreateSessionCapsNotSet(t *testing.T) {
	rsp, err := http.Post(gridrouter("/wd/hub/session"), "", bytes.NewReader([]byte("{}")))

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusBadRequest}, Body{"browser not set"}})
}

func TestCreateSessionBrowserNotSet(t *testing.T) {
	rsp, err := http.Post(gridrouter("/wd/hub/session"), "", bytes.NewReader([]byte(`{"desiredCapabilities":{}}`)))

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusBadRequest}, Body{"browser not set"}})
}

func TestCreateSessionBadBrowserName(t *testing.T) {
	rsp, err := http.Post(gridrouter("/wd/hub/session"), "", bytes.NewReader([]byte(`{"desiredCapabilities":{"browserName":false}}`)))

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusBadRequest}, Body{"browser not set"}})
}

func TestCreateSessionUnsupportedBrowser(t *testing.T) {
	rsp, err := http.Post(gridrouter("/wd/hub/session"), "", bytes.NewReader([]byte(`{"desiredCapabilities":{"browserName":"mosaic", "version":"1.0"}}`)))

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusNotFound}, Body{"unsupported browser: mosaic 1.0"}})
}

func TestCreateSessionNoHosts(t *testing.T) {
	test.Lock()
	defer test.Unlock()

	config = Browsers{Browsers: []Browser{
		Browser{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			Version{Number: "1.0", Regions: []Region{
				Region{Hosts: Hosts{
					Host{Name: "browser-1.0", Port: 4444, Count: 0},
				}},
			}},
		}}}}
	linkRoutes(&config)

	rsp, err := http.Post(gridrouter("/wd/hub/session"), "", bytes.NewReader([]byte(`{"desiredCapabilities":{"browserName":"browser", "version":"1.0"}}`)))

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusInternalServerError}, Body{"cannot create session browser 1.0 on any hosts after 1 attempt(s)"}})
}

func TestCreateSessionHostDown(t *testing.T) {
	test.Lock()
	defer test.Unlock()

	config = Browsers{Browsers: []Browser{
		Browser{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			Version{Number: "1.0", Regions: []Region{
				Region{Hosts: Hosts{
					Host{Name: "browser-1.0", Port: 4444, Count: 1},
				}},
			}},
		}}}}
	linkRoutes(&config)

	rsp, err := http.Post(gridrouter("/wd/hub/session"), "", bytes.NewReader([]byte(`{"desiredCapabilities":{"browserName":"browser", "version":"1.0"}}`)))

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusInternalServerError}, Body{"cannot create session browser 1.0 on any hosts after 1 attempt(s)"}})
}

func TestSessionEmptyHash(t *testing.T) {
	rsp, err := http.Get(gridrouter("/wd/hub/session/"))

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusNotFound}, Body{"route not found"}})
}

func TestSessionWrongHash(t *testing.T) {
	rsp, err := http.Get(gridrouter("/wd/hub/session/012345678901234567890123456789012"))

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusNotFound}, Body{"route not found"}})
}

func TestStartSession(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fmt.Sprintf(`{"sessionId":"123"}`)))
	}))
	selenium := httptest.NewServer(mux)
	defer selenium.Close()

	host, port := hostportnum(selenium.URL)
	node := Host{Name: host, Port: port, Count: 1}

	test.Lock()
	defer test.Unlock()

	config = Browsers{Browsers: []Browser{
		Browser{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			Version{Number: "1.0", Regions: []Region{
				Region{Hosts: Hosts{
					node,
				}},
			}},
		}}}}
	linkRoutes(&config)

	rsp, err := http.Post(gridrouter("/wd/hub/session"), "", bytes.NewReader([]byte(`{"desiredCapabilities":{"browserName":"browser", "version":"1.0"}}`)))

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusOK}, Body{`{"sessionId":"` + node.sum() + `123"}`}})
}

func TestStartSessionFail(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "", http.StatusInternalServerError)
	}))
	selenium := httptest.NewServer(mux)
	defer selenium.Close()

	host, port := hostportnum(selenium.URL)
	node := Host{Name: host, Port: port, Count: 1}

	test.Lock()
	defer test.Unlock()

	config = Browsers{Browsers: []Browser{
		Browser{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			Version{Number: "1.0", Regions: []Region{
				Region{Hosts: Hosts{
					node, node, node, node, node,
				}},
			}},
		}}}}
	linkRoutes(&config)

	rsp, err := http.Post(gridrouter("/wd/hub/session"), "", bytes.NewReader([]byte(`{"desiredCapabilities":{"browserName":"browser", "version":"1.0"}}`)))

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusInternalServerError}, Body{"cannot create session browser 1.0 on any hosts after 5 attempt(s)"}})
}

func TestDeleteSession(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session/", func(w http.ResponseWriter, r *http.Request) {
	})
	selenium := httptest.NewServer(mux)
	defer selenium.Close()

	host, port := hostportnum(selenium.URL)
	node := Host{Name: host, Port: port, Count: 1}

	test.Lock()
	defer test.Unlock()

	config = Browsers{Browsers: []Browser{
		Browser{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			Version{Number: "1.0", Regions: []Region{
				Region{Hosts: Hosts{
					node,
				}},
			}},
		}}}}
	linkRoutes(&config)

	r, _ := http.NewRequest("DELETE", gridrouter("/wd/hub/session/"+node.sum()+"123"), nil)
	rsp, err := http.DefaultClient.Do(r)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, Code{http.StatusOK})
}

func TestProxyRequest(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("response"))
	})
	selenium := httptest.NewServer(mux)
	defer selenium.Close()

	host, port := hostportnum(selenium.URL)
	node := Host{Name: host, Port: port, Count: 1}

	test.Lock()
	defer test.Unlock()

	config = Browsers{Browsers: []Browser{
		Browser{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			Version{Number: "1.0", Regions: []Region{
				Region{Hosts: Hosts{
					node,
				}},
			}},
		}}}}
	linkRoutes(&config)

	rsp, err := http.Get(gridrouter("/wd/hub/session/" + node.sum() + "123"))

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusOK}, Body{"response"}})
}

func TestProxyJsonRequest(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session/", func(w http.ResponseWriter, r *http.Request) {
		var msg map[string]interface{}
		json.NewDecoder(r.Body).Decode(&msg)
		AssertThat(t, msg["sessionId"], Is{nil})
	})
	selenium := httptest.NewServer(mux)
	defer selenium.Close()

	host, port := hostportnum(selenium.URL)
	node := Host{Name: host, Port: port, Count: 1}

	test.Lock()
	defer test.Unlock()

	config = Browsers{Browsers: []Browser{
		Browser{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			Version{Number: "1.0", Regions: []Region{
				Region{Hosts: Hosts{
					node,
				}},
			}},
		}}}}
	linkRoutes(&config)

	http.Post(gridrouter("/wd/hub/session/"+node.sum()+"123"), "", bytes.NewReader([]byte(`{"sessionId":"123"}`)))
}

func TestProxyPlainRequest(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		r.Body.Close()
		AssertThat(t, string(body), EqualTo{"request"})
	})
	selenium := httptest.NewServer(mux)
	defer selenium.Close()

	host, port := hostportnum(selenium.URL)
	node := Host{Name: host, Port: port, Count: 1}

	test.Lock()
	defer test.Unlock()

	config = Browsers{Browsers: []Browser{
		Browser{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			Version{Number: "1.0", Regions: []Region{
				Region{Hosts: Hosts{
					node,
				}},
			}},
		}}}}
	linkRoutes(&config)

	http.Post(gridrouter("/wd/hub/session/"+node.sum()+"123"), "", bytes.NewReader([]byte("request")))
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
