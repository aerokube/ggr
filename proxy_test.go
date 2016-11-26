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
	"strconv"
	"strings"
	"sync"
	"testing"

	. "github.com/aandryashin/matchers"
	"io"
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

type Message struct {
	B string
}

func (m Message) Match(i interface{}) bool {
	rsp := i.(*http.Response)
	var reply map[string]interface{}
	err := json.NewDecoder(rsp.Body).Decode(&reply)
	rsp.Body.Close()
	if err != nil {
		return false
	}
	val, ok := reply["value"].(map[string]interface{})
	if !ok {
		return false
	}
	msg, ok := val["message"].(string)
	if !ok {
		return false
	}
	return EqualTo{m.B}.Match(msg)
}

func (m Message) String() string {
	return fmt.Sprintf("json error message %v", m.B)
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
	req, _ := http.NewRequest("GET", gridrouter("/wd/hub/session"), nil)
	req.SetBasicAuth("test", "test")
	client := &http.Client{}
	rsp, err := client.Do(req)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusMethodNotAllowed}, Body{"method not allowed"}})
}

func TestUnathorized(t *testing.T) {
	rsp, err := http.Post(gridrouter("/wd/hub/session"), "", bytes.NewReader([]byte(`{"desiredCapabilities":{}}`)))

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, Code{http.StatusUnauthorized})
}

func TestCreateSessionEmptyBody(t *testing.T) {
	rsp, err := createSessionFromReader(nil)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusBadRequest}, Body{"bad json format: EOF"}})
}

func TestCreateSessionBadJson(t *testing.T) {
	rsp, err := createSession("")

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusBadRequest}, Body{"bad json format: EOF"}})
}

func TestCreateSessionCapsNotSet(t *testing.T) {
	rsp, err := createSession("{}")

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusBadRequest}, Body{"browser not set"}})
}

func TestCreateSessionBrowserNotSet(t *testing.T) {
	rsp, err := createSession(`{"desiredCapabilities":{}}`)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusBadRequest}, Body{"browser not set"}})
}

func TestCreateSessionBadBrowserName(t *testing.T) {
	rsp, err := createSession(`{"desiredCapabilities":{"browserName":false}}`)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusBadRequest}, Body{"browser not set"}})
}

func TestCreateSessionUnsupportedBrowser(t *testing.T) {
	rsp, err := createSession(`{"desiredCapabilities":{"browserName":"mosaic"}}`)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusNotFound}, Body{"unsupported browser: mosaic"}})
}

func TestCreateSessionUnsupportedBrowserVersion(t *testing.T) {
	rsp, err := createSession(`{"desiredCapabilities":{"browserName":"mosaic", "version":"1.0"}}`)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusNotFound}, Body{"unsupported browser: mosaic-1.0"}})
}

func createSession(capabilities string) (*http.Response, error) {
	body := bytes.NewReader([]byte(capabilities))
	return createSessionFromReader(body)
}

func createSessionFromReader(body io.Reader) (*http.Response, error) {
	req, _ := http.NewRequest("POST", gridrouter("/wd/hub/session"), body)
	req.SetBasicAuth("test", "test")
	client := &http.Client{}
	return client.Do(req)
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
	routes = linkRoutes(&config)

	rsp, err := createSession(`{"desiredCapabilities":{"browserName":"browser", "version":"1.0"}}`)
	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusInternalServerError}, Message{"cannot create session browser-1.0 on any hosts after 1 attempt(s)"}})
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
	routes = linkRoutes(&config)

	rsp, err := createSession(`{"desiredCapabilities":{"browserName":"browser", "version":"1.0"}}`)
	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusInternalServerError}, Message{"cannot create session browser-1.0 on any hosts after 1 attempt(s)"}})
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
		w.Write([]byte(`{"sessionId":"123"}`))
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
	routes = linkRoutes(&config)

	rsp, err := createSession(`{"desiredCapabilities":{"browserName":"browser", "version":"1.0"}}`)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusOK}, Body{`{"sessionId":"` + node.sum() + `123"}`}})
}

func TestStartSessionWithJsonSpecChars(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"sessionId":"123"}`))
	}))
	selenium := httptest.NewServer(mux)
	defer selenium.Close()

	host, port := hostportnum(selenium.URL)
	node := Host{Name: host, Port: port, Count: 1}

	test.Lock()
	defer test.Unlock()

	config = Browsers{Browsers: []Browser{
		Browser{Name: "{browser}", DefaultVersion: "1.0", Versions: []Version{
			Version{Number: "1.0", Regions: []Region{
				Region{Hosts: Hosts{
					node,
				}},
			}},
		}}}}
	routes = linkRoutes(&config)

	rsp, err := createSession(`{"desiredCapabilities":{"browserName":"{browser}", "version":"1.0"}}`)

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
	routes = linkRoutes(&config)

	rsp, err := createSession(`{"desiredCapabilities":{"browserName":"browser", "version":"1.0"}}`)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusInternalServerError}, Message{"cannot create session browser-1.0 on any hosts after 1 attempt(s)"}})
}

func TestStartSessionBrowserFail(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"value": {"message" : "Browser startup failure..."}}`))
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
	routes = linkRoutes(&config)

	rsp, err := createSession(`{"desiredCapabilities":{"browserName":"browser", "version":"1.0"}}`)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusInternalServerError}, Message{"cannot create session browser-1.0 on any hosts after 5 attempt(s)"}})
}

func TestStartSessionBrowserFailUnknownError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{}`))
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
	routes = linkRoutes(&config)

	rsp, err := createSession(`{"desiredCapabilities":{"browserName":"browser", "version":"1.0"}}`)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusInternalServerError}, Message{"cannot create session browser-1.0 on any hosts after 1 attempt(s)"}})
}

func TestStartSessionBrowserFailWrongValue(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"value": 1}`))
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
	routes = linkRoutes(&config)

	rsp, err := createSession(`{"desiredCapabilities":{"browserName":"browser", "version":"1.0"}}`)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusInternalServerError}, Message{"cannot create session browser-1.0 on any hosts after 1 attempt(s)"}})
}

func TestStartSessionBrowserFailWrongMsg(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"value": {"message" : true}}`))
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
	routes = linkRoutes(&config)

	rsp, err := createSession(`{"desiredCapabilities":{"browserName":"browser", "version":"1.0"}}`)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusInternalServerError}, Message{"cannot create session browser-1.0 on any hosts after 1 attempt(s)"}})
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
	routes = linkRoutes(&config)

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
	routes = linkRoutes(&config)

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
	routes = linkRoutes(&config)

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
	routes = linkRoutes(&config)

	http.Post(gridrouter("/wd/hub/session/"+node.sum()+"123"), "", bytes.NewReader([]byte("request")))
}

func TestRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, remote := info(r)
		AssertThat(t, user, EqualTo{"unknown"})
		AssertThat(t, remote, EqualTo{"127.0.0.1"})
	}))

	r, _ := http.NewRequest("GET", srv.URL, nil)
	http.DefaultClient.Do(r)
}

func TestRequestAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, remote := info(r)
		AssertThat(t, user, EqualTo{"user"})
		AssertThat(t, remote, EqualTo{"127.0.0.1"})
	}))

	r, _ := http.NewRequest("GET", srv.URL, nil)
	r.SetBasicAuth("user", "password")
	http.DefaultClient.Do(r)
}

func TestRequestForwarded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, remote := info(r)
		AssertThat(t, user, EqualTo{"unknown"})
		AssertThat(t, remote, EqualTo{"proxy"})
	}))

	r, _ := http.NewRequest("GET", srv.URL, nil)
	r.Header.Set("X-Forwarded-For", "proxy")
	http.DefaultClient.Do(r)
}

func TestRequestAuthForwarded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, remote := info(r)
		AssertThat(t, user, EqualTo{"user"})
		AssertThat(t, remote, EqualTo{"proxy"})
	}))

	r, _ := http.NewRequest("GET", srv.URL, nil)
	r.Header.Set("X-Forwarded-For", "proxy")
	r.SetBasicAuth("user", "password")
	http.DefaultClient.Do(r)
}
