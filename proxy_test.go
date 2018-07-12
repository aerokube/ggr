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
	"sync"
	"testing"

	"context"
	"io"
	"time"

	"strings"

	. "github.com/aandryashin/matchers"
	. "github.com/aandryashin/matchers/httpresp"
	"github.com/abbot/go-http-auth"
	. "github.com/aerokube/ggr/config"
	"golang.org/x/net/websocket"
	"log"
	"os"
	"path/filepath"
)

var (
	srv  *httptest.Server
	test sync.Mutex
)

const (
	user     = "test"
	password = "test"
)

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
	gitRevision = "test-revision"
	verbose = true
}

func gridrouter(p string) string {
	return fmt.Sprintf("%s%s", srv.URL, p)
}

func TestPing(t *testing.T) {
	rsp, err := http.Get(gridrouter("/ping"))

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, Code{http.StatusOK})
	AssertThat(t, rsp.Body, Is{Not{nil}})

	var data map[string]interface{}
	bt, readErr := ioutil.ReadAll(rsp.Body)
	AssertThat(t, readErr, Is{nil})
	jsonErr := json.Unmarshal(bt, &data)
	AssertThat(t, jsonErr, Is{nil})
	_, hasUptime := data["uptime"]
	AssertThat(t, hasUptime, Is{true})
	_, hasLastReloadTime := data["lastReloadTime"]
	AssertThat(t, hasLastReloadTime, Is{true})
	_, hasNumRequests := data["numRequests"]
	AssertThat(t, hasNumRequests, Is{true})
	version, hasVersion := data["version"]
	AssertThat(t, hasVersion, Is{true})
	AssertThat(t, version, EqualTo{"test-revision"})
}

func TestStatus(t *testing.T) {
	rsp, err := http.Get(gridrouter("/wd/hub/status"))

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, Code{http.StatusOK})
	AssertThat(t, rsp.Body, Is{Not{nil}})

	var data map[string]interface{}
	bt, readErr := ioutil.ReadAll(rsp.Body)
	AssertThat(t, readErr, Is{nil})
	jsonErr := json.Unmarshal(bt, &data)
	AssertThat(t, jsonErr, Is{nil})
	value, hasValue := data["value"]
	AssertThat(t, hasValue, Is{true})
	valueMap := value.(map[string]interface{})
	ready, hasReady := valueMap["ready"]
	AssertThat(t, hasReady, Is{true})
	AssertThat(t, ready, Is{true})
	_, hasMessage := valueMap["message"]
	AssertThat(t, hasMessage, Is{true})
}

func TestErr(t *testing.T) {
	rsp, err := http.Get(gridrouter("/err"))

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusNotFound}, Message{"route not found"}})
}

func TestGetHostUnauthorized(t *testing.T) {
	rsp, err := http.Get(gridrouter("/host/some-id"))
	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, Code{http.StatusUnauthorized})
}

func TestGetExistingHost(t *testing.T) {
	correctHost := Host{Name: "example.com", Port: 4444, Count: 1}
	host := testGetHost(t, correctHost.Sum()+"123", http.StatusOK)
	AssertThat(t, host, Not{nil})
	AssertThat(t, *host, EqualTo{correctHost})
}

func TestGetMissingHost(t *testing.T) {
	const missingMD5Sum = "c83ffc064eb27be6124bce2a117d61bb"
	testGetHost(t, missingMD5Sum+"123", http.StatusNotFound)
}

func TestGetHostBadSessionId(t *testing.T) {
	testGetHost(t, "bad-session-id", http.StatusBadRequest)
}

func testGetHost(t *testing.T, sessionID string, statusCode int) *Host {

	test.Lock()
	defer test.Unlock()

	browsers := Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					Host{Name: "example.com", Port: 4444, Count: 1, Username: "test", Password: "test"},
				}},
			}},
		}}}}
	updateQuota(user, browsers)

	rsp, err := doBasicHTTPRequest(http.MethodPost, gridrouter(fmt.Sprintf("/host/%s", sessionID)), nil)
	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, Code{statusCode})
	if statusCode != http.StatusOK {
		return nil
	}
	var host Host
	json.NewDecoder(rsp.Body).Decode(&host)
	return &host
}

func TestGetQuotaInfoUnauthorized(t *testing.T) {
	rsp, err := http.Get(gridrouter("/quota"))
	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, Code{http.StatusUnauthorized})
}

func TestGetQuotaInfo(t *testing.T) {
	test.Lock()
	defer test.Unlock()
	browsers := Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					Host{Name: "example.com", Port: 4444, Count: 1, Username: "test", Password: "test"},
				}},
			}},
		}}}}
	updateQuota(user, browsers)

	rsp, err := doBasicHTTPRequest(http.MethodPost, gridrouter("/quota"), nil)
	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, Code{http.StatusOK})

	var fetchedBrowsers []Browser
	err = json.NewDecoder(rsp.Body).Decode(&fetchedBrowsers)
	AssertThat(t, err, Is{nil})

	browsersWithoutCredentials := []Browser{
		{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					Host{Name: "example.com", Port: 4444, Count: 1, Username: "", Password: ""},
				}},
			}},
		}}}
	AssertThat(t, fetchedBrowsers, EqualTo{browsersWithoutCredentials})
}

func TestProxyScreenVNCProtocol(t *testing.T) {

	test.Lock()
	defer test.Unlock()

	const testData = "vnc-data"
	server := testTCPServer(testData)
	defer server.Close()

	vncHost := Host{Name: "example.com", Port: 4444, Count: 1, VNC: fmt.Sprintf("vnc://%s", server.Addr().String())}

	browsers := Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					vncHost,
				}},
			}},
		}}}}
	updateQuota(user, browsers)

	testDataReceived(vncHost, testData, t)
}

func testDataReceived(host Host, correctData string, t *testing.T) {
	sessionID := host.Sum() + "123"

	origin := "http://localhost/"
	u := fmt.Sprintf("ws://%s/vnc/%s", srv.Listener.Addr(), sessionID)
	ws, err := websocket.Dial(u, "", origin)
	AssertThat(t, err, Is{nil})

	var data = make([]byte, len(correctData))
	_, err = ws.Read(data)
	AssertThat(t, err, Is{nil})
	AssertThat(t, strings.TrimSpace(string(data)), EqualTo{correctData})
}

func testTCPServer(data string) net.Listener {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				continue
			}
			defer conn.Close()
			io.WriteString(conn, data)
			return
		}
	}()
	return l
}

func TestProxyScreenWebSocketsProtocol(t *testing.T) {

	test.Lock()
	defer test.Unlock()

	const testData = "ws-data"
	mux := http.NewServeMux()
	mux.Handle("/vnc/123", websocket.Handler(func(wsconn *websocket.Conn) {
		wsconn.Write([]byte(testData))
	}))

	wsServer := httptest.NewServer(mux)
	defer wsServer.Close()

	wsHost := Host{Name: "example.com", Port: 4444, Count: 1, VNC: fmt.Sprintf("ws://%s/vnc", wsServer.Listener.Addr().String())}

	browsers := Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					wsHost,
				}},
			}},
		}}}}
	updateQuota(user, browsers)

	testDataReceived(wsHost, testData, t)

}

func TestProxyVideoFileWithoutAuth(t *testing.T) {
	rsp, err := http.Get(gridrouter("/video/123"))

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, Code{http.StatusUnauthorized})
}

func TestProxyVideoFile(t *testing.T) {

	test.Lock()
	defer test.Unlock()

	fileServer, sessionID := prepareMockFileServer("/video/123.mp4")
	defer fileServer.Close()

	rsp, err := doBasicHTTPRequest(http.MethodGet, gridrouter(fmt.Sprintf("/video/%s", sessionID)), nil)
	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, Code{http.StatusOK})

	rsp, err = doBasicHTTPRequest(http.MethodGet, gridrouter("/video/missing-file"), nil)
	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, Code{http.StatusNotFound})

	rsp, err = doBasicHTTPRequest(http.MethodGet, gridrouter("/video/f7fd94f75c79c36e547c091632da440f_missing-file"), nil)
	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, Code{http.StatusNotFound})
}

func prepareMockFileServer(path string) (*httptest.Server, string) {
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	fileServer := httptest.NewServer(mux)

	host, port := hostportnum(fileServer.URL)
	node := Host{Name: host, Port: port, Count: 1}

	browsers := Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					node,
				}},
			}},
		}}}}
	updateQuota(user, browsers)

	sessionID := node.Sum() + "123"

	return fileServer, sessionID
}

func TestProxyDownloadWithoutAuth(t *testing.T) {
	rsp, err := http.Get(gridrouter("/download/123"))

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, Code{http.StatusUnauthorized})
}

func TestProxyDownload(t *testing.T) {

	test.Lock()
	defer test.Unlock()

	fileServer, sessionID := prepareMockFileServer("/download/123/somefile.txt")
	defer fileServer.Close()

	rsp, err := doBasicHTTPRequest(http.MethodGet, gridrouter(fmt.Sprintf("/download/%s/somefile.txt", sessionID)), nil)
	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, Code{http.StatusOK})

	rsp, err = doBasicHTTPRequest(http.MethodGet, gridrouter("/download/missing-file"), nil)
	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, Code{http.StatusNotFound})

	rsp, err = doBasicHTTPRequest(http.MethodGet, gridrouter("/download/f7fd94f75c79c36e547c091632da440f_missing-file"), nil)
	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, Code{http.StatusNotFound})
}

func TestCreateSessionGet(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, gridrouter("/wd/hub/session"), nil)
	req.SetBasicAuth("test", "test")
	client := &http.Client{}
	rsp, err := client.Do(req)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusMethodNotAllowed}, Message{"method not allowed"}})
}

func TestUnauthorized(t *testing.T) {
	rsp, err := http.Post(gridrouter("/wd/hub/session"), "", bytes.NewReader([]byte(`{"desiredCapabilities":{}}`)))

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, Code{http.StatusUnauthorized})
}

func TestCreateSessionEmptyBody(t *testing.T) {
	rsp, err := createSessionFromReader(nil)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusBadRequest}, Message{"bad json format: EOF"}})
}

func TestCreateSessionBadJson(t *testing.T) {
	rsp, err := createSession("")

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusBadRequest}, Message{"bad json format: EOF"}})
}

func TestCreateSessionCapsNotSet(t *testing.T) {
	rsp, err := createSession("{}")

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusBadRequest}, Message{"browser not set"}})
}

func TestCreateSessionBrowserNotSet(t *testing.T) {
	rsp, err := createSession(`{"desiredCapabilities":{}}`)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusBadRequest}, Message{"browser not set"}})
}

func TestCreateSessionBadBrowserName(t *testing.T) {
	rsp, err := createSession(`{"desiredCapabilities":{"browserName":false}}`)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusBadRequest}, Message{"browser not set"}})
}

func TestCreateSessionUnsupportedBrowser(t *testing.T) {
	rsp, err := createSession(`{"desiredCapabilities":{"browserName":"mosaic"}}`)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusNotFound}, Message{"unsupported browser: mosaic"}})
}

func TestCreateSessionUnsupportedBrowserVersion(t *testing.T) {
	rsp, err := createSession(`{"desiredCapabilities":{"browserName":"mosaic", "version":"1.0"}}`)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusNotFound}, Message{"unsupported browser: mosaic-1.0"}})
}

func createSession(capabilities string) (*http.Response, error) {
	body := bytes.NewReader([]byte(capabilities))
	return createSessionFromReader(body)
}

func createSessionFromReader(body io.Reader) (*http.Response, error) {
	return doBasicHTTPRequest(http.MethodPost, gridrouter("/wd/hub/session"), body)
}

func doBasicHTTPRequest(method string, url string, body io.Reader) (*http.Response, error) {
	req, _ := http.NewRequest(method, url, body)
	req.SetBasicAuth(user, password)
	client := &http.Client{}
	return client.Do(req)
}

func TestCreateSessionNoHosts(t *testing.T) {
	test.Lock()
	defer test.Unlock()

	browsers := Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					Host{Name: "browser-1.0", Port: 4444, Count: 0},
				}},
			}},
		}}}}
	updateQuota(user, browsers)

	rsp, err := createSession(`{"desiredCapabilities":{"browserName":"browser", "version":"1.0"}}`)
	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusInternalServerError}, Message{"cannot create session browser-1.0 on any hosts after 1 attempt(s)"}})
}

func TestCreateSessionHostDown(t *testing.T) {
	test.Lock()
	defer test.Unlock()

	browsers := Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					Host{Name: "browser-1.0", Port: 4444, Count: 1},
				}},
			}},
		}}}}
	updateQuota(user, browsers)

	rsp, err := createSession(`{"desiredCapabilities":{"browserName":"browser", "version":"1.0"}}`)
	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusInternalServerError}, Message{"cannot create session browser-1.0 on any hosts after 1 attempt(s)"}})
}

func TestSessionEmptyHash(t *testing.T) {
	rsp, err := http.Get(gridrouter("/wd/hub/session/"))

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusNotFound}, Message{"route not found"}})
}

func TestSessionWrongHash(t *testing.T) {
	rsp, err := http.Get(gridrouter("/wd/hub/session/012345678901234567890123456789012"))

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusNotFound}, Message{"route not found"}})
}

func TestStartSession(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"sessionId":"123"}`))
	}))

	browsersProvider := func(node Host) Browsers {
		return Browsers{Browsers: []Browser{
			{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
				{Number: "1.0", Regions: []Region{
					{Hosts: Hosts{
						node,
					}},
				}},
			}},
			{Name: "someDevice", DefaultVersion: "2.0", Versions: []Version{
				{Number: "2.0", Regions: []Region{
					{Hosts: Hosts{
						node,
					}},
				}},
			}}}}
	}

	testStartSession(t, mux, browsersProvider, "browser", "1.0")
	testStartSessionCustomCaps(t, mux, browsersProvider, `{"desiredCapabilities":{"deviceName":"someDevice", "version":"2.0"}}`)
}

func TestStartSessionWithLocationHeader(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://host.example.com/session/123")
	}))

	browsersProvider := func(node Host) Browsers {
		return Browsers{Browsers: []Browser{
			{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
				{Number: "1.0", Regions: []Region{
					{Hosts: Hosts{
						node,
					}},
				}},
			}}}}
	}

	testStartSession(t, mux, browsersProvider, "browser", "1.0")
}

func testStartSessionCustomCaps(t *testing.T, mux *http.ServeMux, browsersProvider func(Host) Browsers, capsJSON string) {
	selenium := httptest.NewServer(mux)
	defer selenium.Close()

	host, port := hostportnum(selenium.URL)
	node := Host{Name: host, Port: port, Count: 1}
	browsers := browsersProvider(node)

	test.Lock()
	defer test.Unlock()

	updateQuota(user, browsers)
	go func() {
		// To detect race conditions in quota loading when session creating
		updateQuota(user, browsers)
	}()

	rsp, err := createSession(capsJSON)

	AssertThat(t, err, Is{nil})
	var sess map[string]interface{}
	AssertThat(t, rsp, AllOf{Code{http.StatusOK}, IsJson{&sess}})
	AssertThat(t, sess["sessionId"], EqualTo{fmt.Sprintf("%s123", node.Sum())})
}

func testStartSession(t *testing.T, mux *http.ServeMux, browsersProvider func(Host) Browsers, browserName string, version string) {
	testStartSessionCustomCaps(t, mux, browsersProvider, fmt.Sprintf(`{"desiredCapabilities":{"browserName":"%s", "version":"%s", "labels": {"one": "value1", "two": null, "three": false}}}`, browserName, version))
}

func TestStartSessionWithJsonSpecChars(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"sessionId":"123"}`))
	}))

	browsersProvider := func(node Host) Browsers {
		return Browsers{Browsers: []Browser{
			{Name: "{browser}", DefaultVersion: "1.0", Versions: []Version{
				{Number: "1.0", Regions: []Region{
					{Hosts: Hosts{
						node,
					}},
				}},
			}}}}
	}

	testStartSession(t, mux, browsersProvider, "{browser}", "1.0")
}

func TestStartSessionWithOverriddenBasicAuth(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if ok && username == "test" && password == "test-password" {
			w.Write([]byte(`{"sessionId":"123"}`))
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))

	browsersProvider := func(node Host) Browsers {
		node.Username = "test"
		node.Password = "test-password"
		return Browsers{Browsers: []Browser{
			{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
				{Number: "1.0", Regions: []Region{
					{Hosts: Hosts{
						node,
					}},
				}},
			}}}}
	}

	testStartSession(t, mux, browsersProvider, "browser", "1.0")
}

func TestStartSessionWithPrefixVersion(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		r.Body.Close()
		var sess map[string]map[string]string
		err := json.Unmarshal(body, &sess)
		AssertThat(t, err, Is{nil})
		AssertThat(t, sess["desiredCapabilities"]["version"], EqualTo{"1.0"})

	}))
	selenium := httptest.NewServer(mux)
	defer selenium.Close()

	host, port := hostportnum(selenium.URL)
	node := Host{Name: host, Port: port, Count: 1}

	test.Lock()
	defer test.Unlock()

	browsers := Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					node,
				}},
			}},
		}}}}
	updateQuota(user, browsers)

	createSession(`{"desiredCapabilities":{"browserName":"browser", "version":"1"}}`)
}

func TestCreateSessionW3CBrowserNotSet0(t *testing.T) {
	rsp, err := createSession(`{"capabilities":{}}`)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusBadRequest}, Message{"browser not set"}})
}

func TestCreateSessionW3CBrowserNotSet1(t *testing.T) {
	rsp, err := createSession(`{"capabilities":{"alwaysMatch":{}}}`)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusBadRequest}, Message{"browser not set"}})
}

func TestCreateSessionW3CBrowserNotSet2(t *testing.T) {
	rsp, err := createSession(`{"capabilities":{"alwaysMatch":{"browserName":false}}}}`)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusBadRequest}, Message{"browser not set"}})
}

func TestStartSessionWithDefaultVersion(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		r.Body.Close()
		w.Write([]byte(`{"sessionId":"123"}`))
		var sess map[string]map[string]string
		err := json.Unmarshal(body, &sess)
		AssertThat(t, err, Is{nil})
		AssertThat(t, sess["desiredCapabilities"]["version"], EqualTo{"2.0"})

	}))
	selenium := httptest.NewServer(mux)
	defer selenium.Close()

	host, port := hostportnum(selenium.URL)
	node := Host{Name: host, Port: port, Count: 1}

	test.Lock()
	defer test.Unlock()

	browsers := Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "2.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					node,
				}},
			}},
			{Number: "2.0", Regions: []Region{
				{Hosts: Hosts{
					node,
				}},
			}},
		}}}}
	updateQuota(user, browsers)

	createSession(`{"desiredCapabilities":{"browserName":"browser"}}`)
}

func TestStartSessionWithDefaultVersionW3C(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		r.Body.Close()
		var sess map[string]map[string]map[string]string
		err := json.Unmarshal(body, &sess)
		w.Write([]byte(`{"sessionId":"123"}`))
		AssertThat(t, err, Is{nil})
		AssertThat(t, sess["capabilities"]["alwaysMatch"]["browserVersion"], EqualTo{"2.0"})

	}))
	selenium := httptest.NewServer(mux)
	defer selenium.Close()

	host, port := hostportnum(selenium.URL)
	node := Host{Name: host, Port: port, Count: 1}

	test.Lock()
	defer test.Unlock()

	browsers := Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "2.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					node,
				}},
			}},
			{Number: "2.0", Regions: []Region{
				{Hosts: Hosts{
					node,
				}},
			}},
		}}}}
	updateQuota(user, browsers)

	createSession(`{"capabilities":{"alwaysMatch":{"browserName":"browser"}}}`)
}

func TestClientClosedConnection(t *testing.T) {
	done := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(10 * time.Second):
		case <-done:
		}
	}))
	selenium := httptest.NewServer(mux)
	defer selenium.Close()

	host, port := hostportnum(selenium.URL)
	node := Host{Name: host, Port: port, Count: 1}

	test.Lock()
	defer test.Unlock()

	browsers := Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					node,
				}},
			}},
		}}}}
	updateQuota(user, browsers)

	r, _ := http.NewRequest(http.MethodPost, gridrouter("/wd/hub/session"), bytes.NewReader([]byte(`{"desiredCapabilities":{"browserName":"browser", "version":"1.0"}}`)))
	r.SetBasicAuth("test", "test")
	ctx, cancel := context.WithCancel(r.Context())
	go func() {
		resp, _ := http.DefaultClient.Do(r.WithContext(ctx))
		if resp != nil {
			defer resp.Body.Close()
		}
		close(done)
	}()
	<-time.After(50 * time.Millisecond)
	cancel()
	<-done
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

	browsers := Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					node, node, node, node, node,
				}},
			}},
		}}}}
	updateQuota(user, browsers)

	rsp, err := createSession(`{"desiredCapabilities":{"browserName":"browser", "version":"1.0"}}`)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusInternalServerError}, Message{"cannot create session browser-1.0 on any hosts after 1 attempt(s)"}})
}

func TestStartSessionFailMultiRegion(t *testing.T) {
	node := []Host{
		Host{Name: "localhost", Port: 9991, Count: 1},
		Host{Name: "localhost", Port: 9992, Count: 1},
		Host{Name: "localhost", Port: 9993, Count: 1},
		Host{Name: "localhost", Port: 9994, Count: 1},
		Host{Name: "localhost", Port: 9995, Count: 1},
		Host{Name: "localhost", Port: 9996, Count: 1},
		Host{Name: "localhost", Port: 9997, Count: 1},
		Host{Name: "localhost", Port: 9998, Count: 1},
		Host{Name: "localhost", Port: 9999, Count: 1},
	}

	test.Lock()
	defer test.Unlock()

	browsers := Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				Region{
					Name: "us-west-1",
					Hosts: Hosts{
						node[0], node[1], node[2],
					},
				},
				Region{
					Name: "us-west-2",
					Hosts: Hosts{
						node[3], node[4], node[5],
					},
				},
				Region{
					Name: "us-west-3",
					Hosts: Hosts{
						node[6], node[7], node[8],
					},
				},
			}},
		}}}}
	updateQuota(user, browsers)

	rsp, err := createSession(`{"desiredCapabilities":{"browserName":"browser", "version":"1.0"}}`)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusInternalServerError}, Message{"cannot create session browser-1.0 on any hosts after 9 attempt(s)"}})
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

	browsers := Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					node, node, node, node, node,
				}},
			}},
		}}}}
	updateQuota(user, browsers)

	rsp, err := createSession(`{"desiredCapabilities":{"browserName":"browser", "version":"1.0"}}`)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusInternalServerError}, Message{"cannot create session browser-1.0 on any hosts after 5 attempt(s), last host error was: Browser startup failure..."}})
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

	browsers := Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					node,
				}},
			}},
		}}}}
	updateQuota(user, browsers)

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

	browsers := Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					node,
				}},
			}},
		}}}}
	updateQuota(user, browsers)

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

	browsers := Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					node,
				}},
			}},
		}}}}
	updateQuota(user, browsers)

	rsp, err := createSession(`{"desiredCapabilities":{"browserName":"browser", "version":"1.0"}}`)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusInternalServerError}, Message{"cannot create session browser-1.0 on any hosts after 1 attempt(s)"}})
}

func TestStartSessionFailJSONWireProtocol(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		//w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(`{}`))
	}))
	selenium := httptest.NewServer(mux)
	defer selenium.Close()

	host, port := hostportnum(selenium.URL)
	node := Host{Name: host, Port: port, Count: 1}

	test.Lock()
	defer test.Unlock()

	browsers := Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					node,
				}},
			}},
		}}}}
	updateQuota(user, browsers)

	rsp, err := createSession(`{"desiredCapabilities":{"browserName":"browser", "version":"1.0"}}`)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusBadGateway}, Message{"protocol error"}})
}

func TestStartSessionFailJSONWireProtocolNoSessionID(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"value":{}}`))
	}))
	selenium := httptest.NewServer(mux)
	defer selenium.Close()

	host, port := hostportnum(selenium.URL)
	node := Host{Name: host, Port: port, Count: 1}

	test.Lock()
	defer test.Unlock()

	browsers := Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					node,
				}},
			}},
		}}}}
	updateQuota(user, browsers)

	rsp, err := createSession(`{"desiredCapabilities":{"browserName":"browser", "version":"1.0"}}`)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusBadGateway}, Message{"protocol error"}})
}

func TestStartSessionFailJSONWireProtocolWrongType(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"value":{"sessionId":123}}`))
	}))
	selenium := httptest.NewServer(mux)
	defer selenium.Close()

	host, port := hostportnum(selenium.URL)
	node := Host{Name: host, Port: port, Count: 1}

	test.Lock()
	defer test.Unlock()

	browsers := Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					node,
				}},
			}},
		}}}}
	updateQuota(user, browsers)

	rsp, err := createSession(`{"desiredCapabilities":{"browserName":"browser", "version":"1.0"}}`)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusBadGateway}, Message{"protocol error"}})
}

func TestStartSessionJSONWireProtocol(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"value":{"sessionId":"123"}}`))
	}))
	selenium := httptest.NewServer(mux)
	defer selenium.Close()

	host, port := hostportnum(selenium.URL)
	node := Host{Name: host, Port: port, Count: 1}

	test.Lock()
	defer test.Unlock()

	browsers := Browsers{Browsers: []Browser{
		{Name: "{browser}", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					node,
				}},
			}},
		}}}}
	updateQuota(user, browsers)

	rsp, err := createSession(`{"desiredCapabilities":{"browserName":"{browser}", "version":"1.0"}}`)

	AssertThat(t, err, Is{nil})
	var value map[string]interface{}
	AssertThat(t, rsp, AllOf{Code{http.StatusOK}, IsJson{&value}})
	AssertThat(t, value["value"].(map[string]interface{})["sessionId"], EqualTo{fmt.Sprintf("%s123", node.Sum())})
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

	browsers := Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					node,
				}},
			}},
		}}}}
	updateQuota(user, browsers)

	r, _ := http.NewRequest(http.MethodDelete, gridrouter("/wd/hub/session/"+node.Sum()+"123"), nil)
	r.SetBasicAuth("test", "test")
	rsp, err := http.DefaultClient.Do(r)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, Code{http.StatusOK})
}

func TestProxyRequest(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"value":{"message":"response"}}`))
	})
	selenium := httptest.NewServer(mux)
	defer selenium.Close()

	host, port := hostportnum(selenium.URL)
	node := Host{Name: host, Port: port, Count: 1}

	test.Lock()
	defer test.Unlock()

	browsers := Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					node,
				}},
			}},
		}}}}
	updateQuota(user, browsers)

	r, _ := http.NewRequest(http.MethodGet, gridrouter("/wd/hub/session/"+node.Sum()+"123"), nil)
	r.SetBasicAuth("test", "test")
	rsp, err := http.DefaultClient.Do(r)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusOK}, Message{"response"}})
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

	browsers := Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					node,
				}},
			}},
		}}}}
	updateQuota(user, browsers)
	go func() {
		// To detect race conditions in quota loading when proxying request
		updateQuota(user, browsers)
	}()

	doBasicHTTPRequest(http.MethodPost, gridrouter("/wd/hub/session/"+node.Sum()+"123"), bytes.NewReader([]byte(`{"sessionId":"123"}`)))
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

	browsers := Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					node,
				}},
			}},
		}}}}
	updateQuota(user, browsers)

	doBasicHTTPRequest(http.MethodPost, gridrouter("/wd/hub/session/"+node.Sum()+"123"), bytes.NewReader([]byte("request")))
}

func TestRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, remote := info(r)
		AssertThat(t, user, EqualTo{"unknown"})
		AssertThat(t, remote, EqualTo{"127.0.0.1"})
	}))

	r, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	http.DefaultClient.Do(r)
}

func TestRequestAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, remote := info(r)
		AssertThat(t, user, EqualTo{"user"})
		AssertThat(t, remote, EqualTo{"127.0.0.1"})
	}))

	r, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	r.SetBasicAuth("user", "password")
	http.DefaultClient.Do(r)
}

func TestRequestForwarded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, remote := info(r)
		AssertThat(t, user, EqualTo{"unknown"})
		AssertThat(t, remote, EqualTo{"proxy"})
	}))

	r, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	r.Header.Set("X-Forwarded-For", "proxy")
	http.DefaultClient.Do(r)
}

func TestRequestAuthForwarded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, remote := info(r)
		AssertThat(t, user, EqualTo{"user"})
		AssertThat(t, remote, EqualTo{"proxy"})
	}))

	r, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	r.Header.Set("X-Forwarded-For", "proxy")
	r.SetBasicAuth("user", "password")
	http.DefaultClient.Do(r)
}

func TestStartSessionProxyHeaders(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		u, _, _ := r.BasicAuth()
		AssertThat(t, u, EqualTo{user})
		w.Write([]byte(`{"sessionId":"123"}`))
	}))
	selenium := httptest.NewServer(mux)
	defer selenium.Close()

	host, port := hostportnum(selenium.URL)
	node := Host{Name: host, Port: port, Count: 1}

	test.Lock()
	defer test.Unlock()

	browsers := Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					node,
				}},
			}},
		}}}}
	updateQuota(user, browsers)

	rsp, err := createSession(`{"desiredCapabilities":{"browserName":"browser", "version":"1.0"}}`)

	AssertThat(t, err, Is{nil})
	var sess map[string]string
	AssertThat(t, rsp, AllOf{Code{http.StatusOK}, IsJson{&sess}})
	AssertThat(t, sess["sessionId"], EqualTo{fmt.Sprintf("%s123", node.Sum())})
}

func TestStartSessionGuest(t *testing.T) {
	guestAccessAllowed = true

	dummyMux := http.NewServeMux()
	dummyMux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"value":{"sessionId":"123"}}`))
	}))
	selenium := httptest.NewServer(dummyMux)
	defer selenium.Close()

	host, port := hostportnum(selenium.URL)
	node := Host{Name: host, Port: port, Count: 1}

	test.Lock()
	defer test.Unlock()

	browsers := Browsers{Browsers: []Browser{
		{Name: "{browser}", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					node,
				}},
			}},
		}}}}
	updateQuota(guestUserName, browsers)

	rsp, err := createSessionWithoutAuthentication(`{"desiredCapabilities":{"browserName":"{browser}", "version":"1.0"}}`)
	AssertThat(t, err, Is{nil})
	var value map[string]interface{}
	AssertThat(t, rsp, AllOf{Code{http.StatusOK}, IsJson{&value}})
	AssertThat(t, value["value"].(map[string]interface{})["sessionId"], EqualTo{fmt.Sprintf("%s123", node.Sum())})
}

func TestStartSessionGuestFailNoQuota(t *testing.T) {
	guestAccessAllowed = true

	dummyMux := http.NewServeMux()
	dummyMux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"value":{"sessionId":"123"}}`))
	}))
	selenium := httptest.NewServer(dummyMux)
	defer selenium.Close()

	test.Lock()
	delete(quota, guestUserName)
	defer test.Unlock()

	rsp, err := createSessionWithoutAuthentication(`{"desiredCapabilities":{"browserName":"{browser}", "version":"1.0"}}`)
	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp, AllOf{Code{http.StatusUnauthorized}, Message{"Guest access is unavailable"}})

}

func TestStartSessionGuestAndCorrectBasicAuth(t *testing.T) {
	guestAccessAllowed = true

	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"sessionId":"123"}`))
	}))

	browsersProvider := func(node Host) Browsers {
		return Browsers{Browsers: []Browser{
			{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
				{Number: "1.0", Regions: []Region{
					{Hosts: Hosts{
						node,
					}},
				}},
			}}}}
	}

	testStartSession(t, mux, browsersProvider, "browser", "1.0")
}

func TestStartSessionGuestModeAndWrongBasicAuth(t *testing.T) {
	guestAccessAllowed = true

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

	browsers := Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					node,
				}},
			}},
		}}}}
	updateQuota(user, browsers)

	body := bytes.NewReader([]byte(fmt.Sprintf(`{"desiredCapabilities":{"browserName":"%s", "version":"%s"}}`, "browser", "1.0")))
	req, _ := http.NewRequest(http.MethodPost, gridrouter("/wd/hub/session"), body)
	req.SetBasicAuth(user, "BAD"+password)
	client := &http.Client{}
	rsp, err := client.Do(req)

	AssertThat(t, err, Is{nil})
	AssertThat(t, rsp.StatusCode, Is{http.StatusUnauthorized})
}

func createSessionWithoutAuthentication(capabilities string) (*http.Response, error) {
	body := bytes.NewReader([]byte(capabilities))
	return doHTTPRequestWithoutAuthentication(http.MethodPost, gridrouter("/wd/hub/session"), body)
}

func doHTTPRequestWithoutAuthentication(method string, url string, body io.Reader) (*http.Response, error) {
	req, _ := http.NewRequest(method, url, body)
	client := &http.Client{}
	return client.Do(req)
}

func TestFileExists(t *testing.T) {
	tmpDir := os.TempDir()
	AssertThat(t, fileExists(tmpDir), Is{false})
	AssertThat(t, fileExists(filepath.Join(tmpDir, "missing-file")), Is{false})
	f, err := ioutil.TempFile(tmpDir, "testfile")
	AssertThat(t, err, Is{nil})
	AssertThat(t, fileExists(f.Name()), Is{true})
}

func TestCreateSessionChangeRegionOnFailure(t *testing.T) {
	var selectedRegions []string

	srv1 := httptest.NewServer(recordingMux("a", &selectedRegions))
	defer srv1.Close()
	srv1Url, _ := url.Parse(srv1.URL)
	srv1Port, _ := strconv.Atoi(srv1Url.Port())

	srv2 := httptest.NewServer(recordingMux("a", &selectedRegions))
	defer srv2.Close()
	srv2Url, _ := url.Parse(srv2.URL)
	srv2Port, _ := strconv.Atoi(srv2Url.Port())

	srv3 := httptest.NewServer(recordingMux("b", &selectedRegions))
	defer srv3.Close()
	srv3Url, _ := url.Parse(srv3.URL)
	srv3Port, _ := strconv.Atoi(srv3Url.Port())

	test.Lock()
	defer test.Unlock()

	browsers := Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{
					Name: "a",
					Hosts: Hosts{
						Host{Name: srv1Url.Hostname(), Port: srv1Port, Count: 1},
						Host{Name: srv2Url.Hostname(), Port: srv2Port, Count: 1},
					},
				},
				{
					Name: "b",
					Hosts: Hosts{
						Host{Name: srv3Url.Hostname(), Port: srv3Port, Count: 1},
					},
				},
			}},
		}}}}
	updateQuota(user, browsers)

	timeout := make(chan struct{})
	go func(timeout chan struct{}) {
		time.Sleep(1 * time.Second)
		close(timeout)
	}(timeout)
loop:
	for {
		select {
		case <-timeout:
			break loop
		default:
		}
		createThreeSessions(t, &selectedRegions)
		if selectedRegions[0] == selectedRegions[1] {
			t.Fatalf("Selected 2 same regions on failure: %v", selectedRegions)
		}
		selectedRegions = []string{}
	}
}

func createThreeSessions(t *testing.T, storage *[]string) {
	log.SetOutput(ioutil.Discard)

	createSession(`{"desiredCapabilities":{"browserName":"browser", "version":"1.0"}}`)

	AssertThat(t, len(*storage), EqualTo{3})
	log.SetOutput(os.Stderr)
}

func recordingMux(region string, storage *[]string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		*storage = append(*storage, region)
		w.WriteHeader(http.StatusInternalServerError)
	})
	return mux
}

func TestPanicGuestQuotaMissingUsersFileAuthPresent(t *testing.T) {
	guestAccessAllowed = true
	users = "missing-file"
	defer func() {
		users = ".htpasswd"
	}()
	authenticator := auth.NewBasicAuthenticator(
		"Some Realm",
		auth.HtpasswdFileProvider(users),
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/", WithSuitableAuthentication(authenticator, func(_ http.ResponseWriter, _ *http.Request) {}))

	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req.SetBasicAuth("test", "test")
	resp, err := http.DefaultClient.Do(req)
	AssertThat(t, err, Is{nil})
	AssertThat(t, resp, Code{http.StatusOK})
}
