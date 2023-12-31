package main

import (
	"bytes"
	"encoding/json"
	"fmt"
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

	"github.com/abbot/go-http-auth"
	. "github.com/aerokube/ggr/config"
	assert "github.com/stretchr/testify/require"
	"golang.org/x/net/websocket"
	"os"
	"path/filepath"
)

var _ = func() bool {
	testing.Init()
	return true
}()

var (
	srv  *httptest.Server
	test sync.Mutex
)

const (
	user     = "test"
	password = "test"
)

func message(i interface{}) string {
	rsp := i.(*http.Response)
	var reply map[string]interface{}
	err := json.NewDecoder(rsp.Body).Decode(&reply)
	_ = rsp.Body.Close()
	if err != nil {
		return ""
	}
	val, ok := reply["value"].(map[string]interface{})
	if !ok {
		return ""
	}
	msg, ok := val["message"].(string)
	if !ok {
		return ""
	}
	return msg
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

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusOK)
	assert.NotNil(t, rsp.Body)

	var data map[string]interface{}
	bt, readErr := io.ReadAll(rsp.Body)
	assert.NoError(t, readErr)
	jsonErr := json.Unmarshal(bt, &data)
	assert.NoError(t, jsonErr)
	_, hasUptime := data["uptime"]
	assert.True(t, hasUptime)
	_, hasLastReloadTime := data["lastReloadTime"]
	assert.True(t, hasLastReloadTime)
	_, hasNumRequests := data["numRequests"]
	assert.True(t, hasNumRequests)
	_, hasNumSessions := data["numSessions"]
	assert.True(t, hasNumSessions)
	version, hasVersion := data["version"]
	assert.True(t, hasVersion)
	assert.Equal(t, version, "test-revision")
}

func TestStatus(t *testing.T) {
	rsp, err := http.Get(gridrouter("/wd/hub/status"))

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusOK)
	assert.NotNil(t, rsp.Body)

	var data map[string]interface{}
	bt, readErr := io.ReadAll(rsp.Body)
	assert.NoError(t, readErr)
	jsonErr := json.Unmarshal(bt, &data)
	assert.NoError(t, jsonErr)
	value, hasValue := data["value"]
	assert.True(t, hasValue)
	valueMap := value.(map[string]interface{})
	ready, hasReady := valueMap["ready"]
	assert.True(t, hasReady)
	assert.Equal(t, ready, true)
	_, hasMessage := valueMap["message"]
	assert.True(t, hasMessage)
}

func TestErr(t *testing.T) {
	rsp, err := http.Get(gridrouter("/err"))

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusNotFound)
	assert.Equal(t, message(rsp), "route not found")
}

func TestGetHostUnauthorized(t *testing.T) {
	rsp, err := http.Get(gridrouter("/host/some-id"))
	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusUnauthorized)
}

func TestGetExistingHost(t *testing.T) {
	correctHost := Host{Name: "example.com", Port: 4444, Count: 1}
	host := testGetHost(t, correctHost.Sum()+"123", http.StatusOK)
	assert.NotNil(t, host)
	assert.Equal(t, *host, correctHost)
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
	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, statusCode)
	if statusCode != http.StatusOK {
		return nil
	}
	var host Host
	_ = json.NewDecoder(rsp.Body).Decode(&host)
	return &host
}

func TestGetQuotaInfoUnauthorized(t *testing.T) {
	rsp, err := http.Get(gridrouter("/quota"))
	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusUnauthorized)
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
	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusOK)

	var fetchedBrowsers []Browser
	err = json.NewDecoder(rsp.Body).Decode(&fetchedBrowsers)
	assert.NoError(t, err)

	browsersWithoutCredentials := []Browser{
		{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					Host{Name: "example.com", Port: 4444, Count: 1, Username: "", Password: ""},
				}},
			}},
		}}}
	assert.Equal(t, fetchedBrowsers, browsersWithoutCredentials)
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

	testDataReceived(vncHost, "vnc", testData, t)
}

func testDataReceived(host Host, api string, correctData string, t *testing.T) {
	sessionID := host.Sum() + "123"

	origin := "http://localhost/"
	u := fmt.Sprintf("ws://%s/%s/%s", srv.Listener.Addr(), api, sessionID)
	ws, err := websocket.Dial(u, "", origin)
	assert.NoError(t, err)

	var data = make([]byte, len(correctData))
	_, err = ws.Read(data)
	assert.NoError(t, err)
	assert.Equal(t, strings.TrimSpace(string(data)), correctData)
}

func testTCPServer(data string) net.Listener {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				continue
			}
			_, _ = io.WriteString(conn, data)
			_ = conn.Close()
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
		_, _ = wsconn.Write([]byte(testData))
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

	testDataReceived(wsHost, "vnc", testData, t)

}

func TestProxyDevtools(t *testing.T) {
	test.Lock()
	defer test.Unlock()

	const testData = "devtools-data"
	mux := http.NewServeMux()
	mux.Handle("/devtools/123", websocket.Handler(func(wsconn *websocket.Conn) {
		_, _ = wsconn.Write([]byte(testData))
	}))

	wsServer := httptest.NewServer(mux)
	defer wsServer.Close()

	h, p, _ := net.SplitHostPort(wsServer.Listener.Addr().String())
	intPort, _ := strconv.Atoi(p)
	wsHost := Host{Name: h, Port: intPort, Count: 1}

	browsers := Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					wsHost,
				}},
			}},
		}}}}
	updateQuota(user, browsers)

	testDataReceived(wsHost, "devtools", testData, t)
}

func TestProxyVideoFileWithoutAuth(t *testing.T) {
	rsp, err := http.Get(gridrouter("/video/123"))

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusUnauthorized)
}

func TestProxyVideoFileIncorrectRootToken(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, gridrouter("/video/123"), nil)
	req.Header.Add("X-Ggr-Root-Token", "wrong-token")
	rsp, err := http.DefaultClient.Do(req)

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusUnauthorized)
}

func TestProxyVideoFile(t *testing.T) {

	test.Lock()
	defer test.Unlock()

	fileServer, sessionID := prepareMockFileServer("/video/123.mp4")
	defer fileServer.Close()

	rsp, err := doBasicHTTPRequest(http.MethodGet, gridrouter(fmt.Sprintf("/video/%s", sessionID)), nil)
	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusOK)

	rootToken = "correct-token"
	defer func() {
		rootToken = ""
	}()
	req, _ := http.NewRequest(http.MethodGet, gridrouter(fmt.Sprintf("/video/%s", sessionID)), nil)
	req.Header.Add("X-Ggr-Root-Token", "correct-token")
	rsp, err = http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusOK)

	rsp, err = doBasicHTTPRequest(http.MethodGet, gridrouter("/video/missing-file"), nil)
	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusNotFound)

	rsp, err = doBasicHTTPRequest(http.MethodGet, gridrouter("/video/f7fd94f75c79c36e547c091632da440f_missing-file"), nil)
	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusNotFound)
}

func TestProxyVideoFileBadGateway(t *testing.T) {
	test.Lock()
	defer test.Unlock()

	node := Host{Name: "missing-host.example.com", Port: 4444, Count: 1}

	browsers := Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{Hosts: Hosts{
					node,
				}},
			}},
		}}}}
	updateQuota(user, browsers)

	rsp, err := doBasicHTTPRequest(http.MethodPost, gridrouter("/video/"+node.Sum()+"123"), bytes.NewReader([]byte("request")))
	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusBadGateway)
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

func TestProxyLogsWithoutAuth(t *testing.T) {
	rsp, err := http.Get(gridrouter("/logs/123"))

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusUnauthorized)
}

func TestProxyLogs(t *testing.T) {

	test.Lock()
	defer test.Unlock()

	fileServer, sessionID := prepareMockFileServer("/logs/123.log")
	defer fileServer.Close()

	rsp, err := doBasicHTTPRequest(http.MethodGet, gridrouter(fmt.Sprintf("/logs/%s", sessionID)), nil)
	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusOK)

	rsp, err = doBasicHTTPRequest(http.MethodGet, gridrouter("/logs/missing-session-id"), nil)
	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusNotFound)

	rsp, err = doBasicHTTPRequest(http.MethodGet, gridrouter("/logs/f7fd94f75c79c36e547c091632da440f_missing-file"), nil)
	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusNotFound)
}

func TestProxyDownloadWithoutAuth(t *testing.T) {
	rsp, err := http.Get(gridrouter("/download/123"))

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusUnauthorized)
}

func TestProxyDownload(t *testing.T) {

	test.Lock()
	defer test.Unlock()

	fileServer, sessionID := prepareMockFileServer("/download/123/somefile.txt")
	defer fileServer.Close()

	rsp, err := doBasicHTTPRequest(http.MethodGet, gridrouter(fmt.Sprintf("/download/%s/somefile.txt", sessionID)), nil)
	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusOK)

	rsp, err = doBasicHTTPRequest(http.MethodGet, gridrouter("/download/missing-file"), nil)
	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusNotFound)

	rsp, err = doBasicHTTPRequest(http.MethodGet, gridrouter("/download/f7fd94f75c79c36e547c091632da440f_missing-file"), nil)
	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusNotFound)
}

func TestProxyClipboardWithoutAuth(t *testing.T) {
	rsp, err := http.Get(gridrouter("/clipboard/123"))

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusUnauthorized)
}

func TestProxyClipboard(t *testing.T) {

	test.Lock()
	defer test.Unlock()

	fileServer, sessionID := prepareMockFileServer("/clipboard/123")
	defer fileServer.Close()

	rsp, err := doBasicHTTPRequest(http.MethodGet, gridrouter(fmt.Sprintf("/clipboard/%s", sessionID)), nil)
	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusOK)

	rsp, err = doBasicHTTPRequest(http.MethodGet, gridrouter("/clipboard/missing-session"), nil)
	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusNotFound)

	rsp, err = doBasicHTTPRequest(http.MethodGet, gridrouter("/clipboard/f7fd94f75c79c36e547c091632da440f_missing-session"), nil)
	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusNotFound)
}

func TestCreateSessionGet(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, gridrouter("/wd/hub/session"), nil)
	req.SetBasicAuth("test", "test")
	client := &http.Client{}
	rsp, err := client.Do(req)

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusMethodNotAllowed)
	assert.Equal(t, message(rsp), "method not allowed")
}

func TestUnauthorized(t *testing.T) {
	rsp, err := http.Post(gridrouter("/wd/hub/session"), "", bytes.NewReader([]byte(`{"desiredCapabilities":{}}`)))

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusUnauthorized)
}

func TestCreateSessionEmptyBody(t *testing.T) {
	rsp, err := createSessionFromReader(nil)

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusBadRequest)
	assert.Equal(t, message(rsp), "bad json format: EOF")
}

func TestCreateSessionBadJson(t *testing.T) {
	rsp, err := createSession("")

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusBadRequest)
	assert.Equal(t, message(rsp), "bad json format: EOF")
}

func TestCreateSessionCapsNotSet(t *testing.T) {
	rsp, err := createSession("{}")

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusBadRequest)
	assert.Equal(t, message(rsp), "browser not set")
}

func TestCreateSessionBrowserNotSet(t *testing.T) {
	rsp, err := createSession(`{"desiredCapabilities":{}}`)

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusBadRequest)
	assert.Equal(t, message(rsp), "browser not set")
}

func TestCreateSessionBadBrowserName(t *testing.T) {
	rsp, err := createSession(`{"desiredCapabilities":{"browserName":false}}`)

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusBadRequest)
	assert.Equal(t, message(rsp), "browser not set")
}

func TestCreateSessionUnsupportedBrowser(t *testing.T) {
	rsp, err := createSession(`{"desiredCapabilities":{"browserName":"mosaic"}}`)

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusNotFound)
	assert.Equal(t, message(rsp), "unsupported browser: mosaic")
}

func TestCreateSessionUnsupportedBrowserVersion(t *testing.T) {
	rsp, err := createSession(`{"desiredCapabilities":{"browserName":"mosaic", "version":"1.0"}}`)

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusNotFound)
	assert.Equal(t, message(rsp), "unsupported browser: mosaic-1.0")
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

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusInternalServerError)
	assert.Equal(t, message(rsp), "cannot create session browser-1.0 on any hosts after 1 attempt(s)")
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
	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusInternalServerError)
	assert.Equal(t, message(rsp), "cannot create session browser-1.0 on any hosts after 1 attempt(s)")
}

func TestSessionEmptyHash(t *testing.T) {
	rsp, err := http.Get(gridrouter("/wd/hub/session/"))

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusNotFound)
	assert.Equal(t, message(rsp), "route not found")
}

func TestSessionWrongHash(t *testing.T) {
	rsp, err := http.Get(gridrouter("/wd/hub/session/012345678901234567890123456789012"))

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusNotFound)
	assert.Equal(t, message(rsp), "route not found")
}

func TestStartSession(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"sessionId":"123"}`))
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

	assert.NoError(t, err)
	var sess map[string]interface{}
	assert.Equal(t, rsp.StatusCode, http.StatusOK)
	assert.NoError(t, json.NewDecoder(rsp.Body).Decode(&sess))
	assert.Equal(t, sess["sessionId"], fmt.Sprintf("%s123", node.Sum()))
}

func testStartSession(t *testing.T, mux *http.ServeMux, browsersProvider func(Host) Browsers, browserName string, version string) {
	testStartSessionCustomCaps(t, mux, browsersProvider, fmt.Sprintf(`{"desiredCapabilities":{"browserName":"%s", "version":"%s", "labels": {"one": "value1", "two": null, "three": false}}}`, browserName, version))
}

func TestStartSessionWithJsonSpecChars(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"sessionId":"123"}`))
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
			_, _ = w.Write([]byte(`{"sessionId":"123"}`))
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
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		var sess map[string]map[string]string
		err := json.Unmarshal(body, &sess)
		assert.NoError(t, err)
		assert.Equal(t, sess["desiredCapabilities"]["version"], "1.0")

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

	_, _ = createSession(`{"desiredCapabilities":{"browserName":"browser", "version":"1"}}`)
}

func TestCreateSessionW3CBrowserNotSet0(t *testing.T) {
	rsp, err := createSession(`{"capabilities":{}}`)

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusBadRequest)
	assert.Equal(t, message(rsp), "browser not set")
}

func TestCreateSessionW3CBrowserNotSet1(t *testing.T) {
	rsp, err := createSession(`{"capabilities":{"alwaysMatch":{}}}`)

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusBadRequest)
	assert.Equal(t, message(rsp), "browser not set")
}

func TestCreateSessionW3CBrowserNotSet2(t *testing.T) {
	rsp, err := createSession(`{"capabilities":{"alwaysMatch":{"browserName":false}}}}`)

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusBadRequest)
	assert.Equal(t, message(rsp), "browser not set")
}

func TestStartSessionWithDefaultVersion(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		_, _ = w.Write([]byte(`{"sessionId":"123"}`))
		var sess map[string]map[string]string
		err := json.Unmarshal(body, &sess)
		assert.NoError(t, err)
		assert.Equal(t, sess["desiredCapabilities"]["version"], "2.0")

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

	_, _ = createSession(`{"desiredCapabilities":{"browserName":"browser"}}`)
}

func TestStartSessionWithDefaultVersionW3C(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		var sess map[string]map[string]map[string]interface{}
		err := json.Unmarshal(body, &sess)
		_, _ = w.Write([]byte(`{"sessionId":"123"}`))
		assert.NoError(t, err)
		assert.Equal(t, sess["capabilities"]["alwaysMatch"]["browserVersion"], "2.0")

		so, ok := sess["capabilities"]["alwaysMatch"]["selenoid:options"]
		assert.True(t, ok)
		selenoidOptions, ok := so.(map[string]interface{})
		assert.True(t, ok)
		_, ok = selenoidOptions["browserVersion"]
		assert.False(t, ok)
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

	_, _ = createSession(`{"capabilities":{"alwaysMatch":{"browserName":"browser", "selenoid:options": {"labels": {"some-key": "some-value"}}}}}`)
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

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusInternalServerError)
	assert.Equal(t, message(rsp), "cannot create session browser-1.0 on any hosts after 1 attempt(s)")
}

func TestStartSessionFailMultiRegion(t *testing.T) {
	node := []Host{
		{Name: "localhost", Port: 9991, Count: 1},
		{Name: "localhost", Port: 9992, Count: 1},
		{Name: "localhost", Port: 9993, Count: 1},
		{Name: "localhost", Port: 9994, Count: 1},
		{Name: "localhost", Port: 9995, Count: 1},
		{Name: "localhost", Port: 9996, Count: 1},
		{Name: "localhost", Port: 9997, Count: 1},
		{Name: "localhost", Port: 9998, Count: 1},
		{Name: "localhost", Port: 9999, Count: 1},
	}

	test.Lock()
	defer test.Unlock()

	browsers := Browsers{Browsers: []Browser{
		{Name: "browser", DefaultVersion: "1.0", Versions: []Version{
			{Number: "1.0", Regions: []Region{
				{
					Name: "us-west-1",
					Hosts: Hosts{
						node[0], node[1], node[2],
					},
				},
				{
					Name: "us-west-2",
					Hosts: Hosts{
						node[3], node[4], node[5],
					},
				},
				{
					Name: "us-west-3",
					Hosts: Hosts{
						node[6], node[7], node[8],
					},
				},
			}},
		}}}}
	updateQuota(user, browsers)

	rsp, err := createSession(`{"desiredCapabilities":{"browserName":"browser", "version":"1.0"}}`)

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusInternalServerError)
	assert.Equal(t, message(rsp), "cannot create session browser-1.0 on any hosts after 9 attempt(s)")
}

func TestStartSessionBrowserFail(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"value": {"message" : "Browser startup failure..."}}`))
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

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusInternalServerError)
	assert.Equal(t, message(rsp), "cannot create session browser-1.0 on any hosts after 5 attempt(s), last host error was: Browser startup failure...")
}

func TestStartSessionBrowserFailUnknownError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{}`))
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

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusInternalServerError)
	assert.Equal(t, message(rsp), "cannot create session browser-1.0 on any hosts after 1 attempt(s)")
}

func TestStartSessionBrowserFailWrongValue(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"value": 1}`))
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

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusInternalServerError)
	assert.Equal(t, message(rsp), "cannot create session browser-1.0 on any hosts after 1 attempt(s)")
}

func TestStartSessionBrowserFailWrongMsg(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"value": {"message" : true}}`))
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

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusInternalServerError)
	assert.Equal(t, message(rsp), "cannot create session browser-1.0 on any hosts after 1 attempt(s)")
}

func TestStartSessionFailJSONWireProtocol(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		//w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{}`))
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

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusBadGateway)
	assert.Equal(t, message(rsp), "protocol error")
}

func TestStartSessionFailJSONWireProtocolNoSessionID(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"value":{}}`))
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

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusBadGateway)
	assert.Equal(t, message(rsp), "protocol error")
}

func TestStartSessionFailJSONWireProtocolWrongType(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"value":{"sessionId":123}}`))
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

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusBadGateway)
	assert.Equal(t, message(rsp), "protocol error")
}

func TestStartSessionJSONWireProtocol(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"value":{"sessionId":"123"}}`))
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

	assert.NoError(t, err)
	var value map[string]interface{}
	assert.Equal(t, rsp.StatusCode, http.StatusOK)
	assert.NoError(t, json.NewDecoder(rsp.Body).Decode(&value))
	assert.Equal(t, value["value"].(map[string]interface{})["sessionId"], fmt.Sprintf("%s123", node.Sum()))
}

func TestPanicRouteProtocolError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"value":[]}`))
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

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusBadGateway)
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

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusOK)
}

func TestProxyRequest(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"value":{"message":"response"}}`))
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

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusOK)
	assert.Equal(t, message(rsp), "response")
}

func TestProxyJsonRequest(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session/", func(w http.ResponseWriter, r *http.Request) {
		var msg map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&msg)
		assert.Nil(t, msg["sessionId"])
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

	_, _ = doBasicHTTPRequest(http.MethodPost, gridrouter("/wd/hub/session/"+node.Sum()+"123"), bytes.NewReader([]byte(`{"sessionId":"123"}`)))
}

func TestProxyPlainRequest(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		assert.Equal(t, string(body), "request")
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

	_, _ = doBasicHTTPRequest(http.MethodPost, gridrouter("/wd/hub/session/"+node.Sum()+"123"), bytes.NewReader([]byte("request")))
}

func TestProxyHttpsHost(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {})
	selenium := httptest.NewTLSServer(mux)
	defer selenium.Close()

	host, port := hostportnum(selenium.URL)
	node := Host{Name: host, Port: port, Count: 1, Scheme: "https"}

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

	// We replace default HTTP transport to correctly handle self-signed test TLS certificate
	oldTransport := http.DefaultTransport
	http.DefaultTransport = selenium.Client().Transport
	defer func() {
		http.DefaultTransport = oldTransport
	}()

	rsp, err := doBasicHTTPRequest(http.MethodPost, gridrouter("/wd/hub/session/"+node.Sum()+"123"), bytes.NewReader([]byte("request")))

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusOK)
}

func TestRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, remote := info(r)
		assert.Equal(t, user, "unknown")
		assert.Equal(t, remote, "127.0.0.1")
	}))

	r, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	_, _ = http.DefaultClient.Do(r)
}

func TestRequestAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, remote := info(r)
		assert.Equal(t, user, "user")
		assert.Equal(t, remote, "127.0.0.1")
	}))

	r, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	r.SetBasicAuth("user", "password")
	_, _ = http.DefaultClient.Do(r)
}

func TestRequestForwarded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, remote := info(r)
		assert.Equal(t, user, "unknown")
		assert.Equal(t, remote, "proxy")
	}))

	r, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	r.Header.Set("X-Forwarded-For", "proxy")
	_, _ = http.DefaultClient.Do(r)
}

func TestRequestAuthForwarded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, remote := info(r)
		assert.Equal(t, user, "user")
		assert.Equal(t, remote, "proxy")
	}))

	r, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	r.Header.Set("X-Forwarded-For", "proxy")
	r.SetBasicAuth("user", "password")
	_, _ = http.DefaultClient.Do(r)
}

func TestStartSessionProxyHeaders(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		u, _, _ := r.BasicAuth()
		assert.Equal(t, u, user)
		_, _ = w.Write([]byte(`{"sessionId":"123"}`))
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

	assert.NoError(t, err)
	var sess map[string]interface{}
	assert.Equal(t, rsp.StatusCode, http.StatusOK)
	assert.NoError(t, json.NewDecoder(rsp.Body).Decode(&sess))
	assert.Equal(t, sess["sessionId"], fmt.Sprintf("%s123", node.Sum()))
}

func TestStartSessionGuest(t *testing.T) {
	guestAccessAllowed = true

	dummyMux := http.NewServeMux()
	dummyMux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"value":{"sessionId":"123"}}`))
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
	assert.NoError(t, err)
	var value map[string]interface{}
	assert.Equal(t, rsp.StatusCode, http.StatusOK)
	assert.NoError(t, json.NewDecoder(rsp.Body).Decode(&value))
	assert.Equal(t, value["value"].(map[string]interface{})["sessionId"], fmt.Sprintf("%s123", node.Sum()))
}

func TestStartSessionGuestFailNoQuota(t *testing.T) {
	guestAccessAllowed = true

	dummyMux := http.NewServeMux()
	dummyMux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"value":{"sessionId":"123"}}`))
	}))
	selenium := httptest.NewServer(dummyMux)
	defer selenium.Close()

	test.Lock()
	delete(quota, guestUserName)
	defer test.Unlock()

	rsp, err := createSessionWithoutAuthentication(`{"desiredCapabilities":{"browserName":"{browser}", "version":"1.0"}}`)
	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusUnauthorized)
	assert.Equal(t, message(rsp), "Guest access is unavailable")
}

func TestStartSessionGuestAndCorrectBasicAuth(t *testing.T) {
	guestAccessAllowed = true

	mux := http.NewServeMux()
	mux.HandleFunc("/wd/hub/session", postOnly(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"sessionId":"123"}`))
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
		_, _ = w.Write([]byte(`{"sessionId":"123"}`))
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

	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusUnauthorized)
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
	assert.False(t, fileExists(tmpDir))
	assert.False(t, fileExists(filepath.Join(tmpDir, "missing-file")))
	f, err := os.CreateTemp(tmpDir, "testfile")
	assert.NoError(t, err)
	assert.True(t, fileExists(f.Name()))
}

func TestPanicGuestQuotaMissingUsersFileAuthPresent(t *testing.T) {
	guestAccessAllowed = true
	users = "missing-file"
	defer func() {
		users = ".htpasswd"
	}()
	authenticator := &auth.BasicAuth{
		Realm:   "Some Realm",
		Secrets: auth.HtpasswdFileProvider(users),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", WithSuitableAuthentication(authenticator, func(_ http.ResponseWriter, _ *http.Request) {}))

	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req.SetBasicAuth("test", "test")
	rsp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, rsp.StatusCode, http.StatusOK)
}

func TestPlatformCapability(t *testing.T) {
	var caps caps
	testCaps := `{"desiredCapabilities": {"platformName": "WINDOWS"}, "capabilities": {"platformName": "windows"}}`
	_ = json.Unmarshal([]byte(testCaps), &caps)

	assert.Equal(t, caps.platform(), "WINDOWS")
}

func TestLabelsCapabilityFromExtensions(t *testing.T) {
	var caps caps
	testCaps := `{"capabilities": {"alwaysMatch":{"ggr:options": {"labels": {"some-key": "some-value"}}}}}`
	_ = json.Unmarshal([]byte(testCaps), &caps)
	assert.Equal(t, caps.labels(), "some-key=some-value")
}
