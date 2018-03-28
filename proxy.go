package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/abbot/go-http-auth"
	"golang.org/x/net/websocket"
)

const (
	browserStarted = iota
	browserFailed
	seleniumError
)

const (
	pingPath       = "/ping"
	errPath        = "/err"
	hostPath       = "/host/"
	quotaPath      = "/quota"
	routePath      = "/wd/hub/session"
	proxyPath      = routePath + "/"
	vncPath        = "/vnc/"
	videoPath      = "/video/"
	head           = len(proxyPath)
	md5SumLength   = 32
	tail           = head + md5SumLength
	sessPart       = 4 // /wd/hub/session/{various length session}
	defaultVNCPort = "5900"
	vncScheme      = "vnc"
	wsScheme       = "ws"
)

var keys = struct {
	desiredCapabilities string
	w3cCapabilities     string
	alwaysMatch         string
}{
	desiredCapabilities: "desiredCapabilities",
	w3cCapabilities:     "capabilities",
	alwaysMatch:         "alwaysMatch",
}

var (
	httpClient = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	quota    = make(map[string]Browsers)
	routes   = make(Routes)
	num      uint64
	numLock  sync.RWMutex
	confLock sync.RWMutex
)

// Routes - an MD5 to host map
type Routes map[string]*Host

type caps map[string]interface{}

func (c caps) capabilities(fn func(m map[string]interface{}, w3c bool)) {
	if desiredCapabilities, ok := c[keys.desiredCapabilities]; ok {
		if m, ok := desiredCapabilities.(map[string]interface{}); ok {
			fn(m, false)
		}
	} else {
		if w3cCapabilities, ok := c[keys.w3cCapabilities]; ok {
			if m, ok := w3cCapabilities.(map[string]interface{}); ok {
				if alwaysMatch, ok := m[keys.alwaysMatch]; ok {
					if m, ok := alwaysMatch.(map[string]interface{}); ok {
						fn(m, true)
					}
				}
			}
		}
	}
	fn(make(map[string]interface{}), false)
}

func (c caps) capability(k string) string {
	return c.capabilityJsonWireW3C(k, k)
}

func (c caps) capabilityJsonWireW3C(jsonWire, W3C string) string {
	ch := make(chan string)
	go func(ch chan string) {
		c.capabilities(func(m map[string]interface{}, w3c bool) {
			k := jsonWire
			if w3c {
				k = W3C
			}
			if v, ok := m[k].(string); ok {
				ch <- v
			}
			ch <- ""
		})
	}(ch)
	return <-ch
}

func (c *caps) browser() string {
	browserName := c.capability("browserName")
	if browserName != "" {
		return browserName
	}
	return c.capability("deviceName")
}

func (c caps) cRequestId() string {
		return c.capability("custom.requestId")
}

func (c caps) version() string {
	return c.capabilityJsonWireW3C("version", "browserVersion")
}

func (c caps) setVersion(version string) {
	c.capabilities(func(m map[string]interface{}, w3c bool) {
		if w3c {
			m["browserVersion"] = version
		} else {
			m["version"] = version
		}
	})
}

func (h *Host) session(ctx context.Context, header http.Header, c caps) (map[string]interface{}, int) {
	b, _ := json.Marshal(c)
	req, err := http.NewRequest(http.MethodPost, h.sessionURL(), bytes.NewReader(b))
	if err != nil {
		return nil, seleniumError
	}
	for key, values := range header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	if h.Username != "" && h.Password != "" {
		req.SetBasicAuth(h.Username, h.Password)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, seleniumError
	}
	location := resp.Header.Get("Location")
	if location != "" {
		l, err := url.Parse(location)
		if err != nil {
			return nil, seleniumError
		}
		fragments := strings.Split(l.Path, "/")
		return map[string]interface{}{"sessionId": fragments[len(fragments)-1], "status": 0, "value": struct{}{}}, browserStarted
	}
	var reply map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&reply)
	if err != nil {
		return nil, seleniumError
	}
	if resp.StatusCode != http.StatusOK {
		return reply, browserFailed
	}
	return reply, browserStarted
}

func reply(w http.ResponseWriter, msg map[string]interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(msg)
}

func serial() uint64 {
	numLock.Lock()
	defer numLock.Unlock()
	id := num
	num++
	return id
}

func getSerial() uint64 {
	numLock.RLock()
	defer numLock.RUnlock()
	return num
}

func info(r *http.Request) (user, remote string) {
	if guestAccessAllowed {
		user = guestUserName
	} else {
		user = "unknown"
	}
	if u, _, ok := r.BasicAuth(); ok {
		user = u
	}
	remote = r.Header.Get("X-Forwarded-For")
	if remote != "" {
		return
	}
	remote, _, _ = net.SplitHostPort(r.RemoteAddr)
	return
}

func fmtBrowser(browser, version string) string {
	if version != "" {
		return fmt.Sprintf("%s-%s", browser, version)
	}
	return browser
}

func browserErrMsg(js map[string]interface{}) string {
	if js == nil {
		return ""
	}
	val, ok := js["value"].(map[string]interface{})
	if !ok {
		return ""
	}
	msg, ok := val["message"].(string)
	if !ok {
		return ""
	}
	return msg
}

func errMsg(msg string) map[string]interface{} {
	return map[string]interface{}{
		"value": map[string]string{
			"message": msg,
		},
		"status": 13,
	}
}

func route(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	id := serial()
	user, remote := info(r)
	var c caps
	err := json.NewDecoder(r.Body).Decode(&c)
	cRequestId := c.cRequestId()
	if err != nil {
		reply(w, errMsg(fmt.Sprintf("bad json format: %s", err.Error())), http.StatusBadRequest)
		log.Printf("[%s] [%d] [%.2fs] [BAD_JSON] [%s] [%s] [-] [-] [-] [-] [%v]\n", cRequestId, id, secondsSince(start), user, remote, err)
		return
	}
	browser, version := c.browser(), c.version()
	if browser == "" {
		reply(w, errMsg("browser not set"), http.StatusBadRequest)
		log.Printf("[%s] [%d] [%.2fs] [BROWSER_NOT_SET] [%s] [%s] [-] [-] [-] [-] [-]\n", cRequestId, id, secondsSince(start), user, remote)
		return
	}
	count := 0
	confLock.RLock()
	browsers := quota[user]
	excludedHosts := newSet()
	hosts, version, excludedRegions := browsers.find(browser, version, excludedHosts, newSet())
	confLock.RUnlock()

	if len(hosts) == 0 {
		reply(w, errMsg(fmt.Sprintf("unsupported browser: %s", fmtBrowser(browser, version))), http.StatusNotFound)
		log.Printf("[%s] [%d] [%.2fs] [UNSUPPORTED_BROWSER] [%s] [%s] [%s] [-] [-] [-] [-]\n", cRequestId, id, secondsSince(start), user, remote, fmtBrowser(browser, version))
		return
	}
	lastHostError := ""
loop:
	for h, i := hosts.choose(); ; h, i = hosts.choose() {
		count++
		r.Header.Del("X-Selenoid-No-Wait")
		if len(hosts) != 1 {
			r.Header.Add("X-Selenoid-No-Wait", "")
		}
		if h == nil {
			break loop
		}
		log.Printf("[%s] [%d] [%.2fs] [SESSION_ATTEMPTED] [%s] [%s] [%s] [%s] [-] [%d] [-]\n", cRequestId, id, secondsSince(start), user, remote, fmtBrowser(browser, version), h.net(), count)
		c.setVersion(version)
		resp, status := h.session(r.Context(), r.Header, c)
		select {
		case <-r.Context().Done():
			log.Printf("[%s] [%d] [%.2fs] [CLIENT_DISCONNECTED] [%s] [%s] [%s] [%s] [-] [%d] [-]\n", cRequestId, id, secondsSince(start), user, remote, fmtBrowser(browser, version), h.net(), count)
			return
		default:
		}
		switch status {
		case browserStarted:
			sess, ok := resp["sessionId"].(string)
			if !ok {
				protocolError := func() {
					reply(w, errMsg("protocol error"), http.StatusBadGateway)
					log.Printf("[%s] [%d] [%.2fs] [BAD_RESPONSE] [%s] [%s] [%s] [%s] [-] [-] [-]\n", cRequestId, id, secondsSince(start), user, remote, fmtBrowser(browser, version), h.net())
				}
				value, ok := resp["value"]
				if !ok {
					protocolError()
					return
				}
				sess, ok = value.(map[string]interface{})["sessionId"].(string)
				if !ok {
					protocolError()
					return
				}
				resp["value"].(map[string]interface{})["sessionId"] = h.sum() + sess
			} else {
				resp["sessionId"] = h.sum() + sess
			}
			reply(w, resp, http.StatusOK)
			log.Printf("[%s] [%d] [%.2fs] [SESSION_CREATED] [%s] [%s] [%s] [%s] [%s] [%d] [-]\n", cRequestId, id, secondsSince(start), user, remote, fmtBrowser(browser, version), h.net(), sess, count)
			return
		case browserFailed:
			hosts = append(hosts[:i], hosts[i+1:]...)
		case seleniumError:
			excludedHosts.add(h.net())
			excludedRegions.add(h.region)
			hosts, version, excludedRegions = browsers.find(browser, version, excludedHosts, excludedRegions)
		}
		errMsg := browserErrMsg(resp)
		log.Printf("[%s] [%d] [%.2fs] [SESSION_FAILED] [%s] [%s] [%s] [%s] [-] [%d] [%s]\n", cRequestId, id, secondsSince(start), user, remote, fmtBrowser(browser, version), h.net(), count, errMsg)
		lastHostError = errMsg
		if len(hosts) == 0 {
			break loop
		}
	}
	notCreatedMsg := fmt.Sprintf("cannot create session %s on any hosts after %d attempt(s)", fmtBrowser(browser, version), count)
	if len(lastHostError) > 0 {
		notCreatedMsg = fmt.Sprintf("%s, last host error was: %s", notCreatedMsg, lastHostError)
	}
	reply(w, errMsg(notCreatedMsg), http.StatusInternalServerError)
	log.Printf("[%s] [%d] [%.2fs] [SESSION_NOT_CREATED] [%s] [%s] [%s] [-] [-] [-] [-]\n", cRequestId, id, secondsSince(start), user, remote, fmtBrowser(browser, version))
}

func secondsSince(start time.Time) float64 {
	return float64(time.Now().Sub(start).Seconds())
}

func proxy(r *http.Request) {
	id := serial()
	_, remote := info(r)
	r.URL.Scheme = "http"
	if len(r.URL.Path) > tail {
		sum := r.URL.Path[head:tail]
		proxyPath := r.URL.Path[:head] + r.URL.Path[tail:]
		confLock.RLock()
		h, ok := routes[sum]
		confLock.RUnlock()
		if ok {
			if r.Body != nil {
				if body, err := ioutil.ReadAll(r.Body); err == nil {
					r.Body.Close()
					var msg map[string]interface{}
					if err := json.Unmarshal(body, &msg); err == nil {
						delete(msg, "sessionId")
						body, _ = json.Marshal(msg)
						r.ContentLength = int64(len(body))
					}
					r.Body = ioutil.NopCloser(bytes.NewReader(body))
				}
			}
			r.Host = h.net()
			r.URL.Host = h.net()
			r.URL.Path = proxyPath
			fragments := strings.Split(proxyPath, "/")
			sess := fragments[sessPart]
			if verbose {
				log.Printf("[-] [%d] [-] [PROXYING] [-] [%s] [-] [%s] [%s] [-] [%s]\n", id, remote, h.net(), sess, proxyPath)
			}
			if r.Method == http.MethodDelete && len(fragments) == sessPart+1 {
				log.Printf("[-] [%d] [-] [SESSION_DELETED] [-] [%s] [-] [%s] [%s] [-] [-]\n", id, remote, h.net(), sess)
			}
			return
		}
		log.Printf("[-] [%d] [-] [ROUTE_NOT_FOUND] [-] [%s] [%s] [-] [-] [-] [-]\n", id, remote, proxyPath)
	} else {
		log.Printf("[-] [%d] [-] [INVALID_URL] [-] [%s] [%s] [-] [-] [-] [-]\n", id, remote, r.URL.Path)
	}
	r.URL.Host = listen
	r.URL.Path = errPath
}

func ping(w http.ResponseWriter, _ *http.Request) {
	confLock.RLock()
	defer confLock.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		Uptime         string `json:"uptime"`
		LastReloadTime string `json:"lastReloadTime"`
		NumRequests    uint64 `json:"numRequests"`
		Version        string `json:"version"`
	}{time.Since(startTime).String(), lastReloadTime.String(), getSerial(), gitRevision})
}

func err(w http.ResponseWriter, _ *http.Request) {
	reply(w, errMsg("route not found"), http.StatusNotFound)
}

func host(w http.ResponseWriter, r *http.Request) {
	confLock.RLock()
	defer confLock.RUnlock()

	id := serial()
	user, remote := info(r)
	head := len(hostPath)
	tail := head + md5SumLength
	path := r.URL.Path
	if len(path) < tail {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid session ID"))
		return
	}
	sum := path[head:tail]
	h, ok := routes[sum]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("unknown host"))
		return
	}
	log.Printf("[-] [%d] [-] [HOST_INFO_REQUESTED] [%s] [%s] [-] [%s] [%s] [-] [-]\n", id, user, remote, h.Name, sum)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Host{Name: h.Name, Port: h.Port, Count: h.Count})
}

func quotaInfo(w http.ResponseWriter, r *http.Request) {
	confLock.RLock()
	defer confLock.RUnlock()
	id := serial()
	user, remote := info(r)
	log.Printf("[-] [%d] [-] [QUOTA_INFO_REQUESTED] [%s] [%s] [-] [-] [-] [-] [-]\n", id, user, remote)
	browsers := quota[user]
	w.Header().Set("Content-Type", "application/json")
	// NOTE: intentionally not removing username \ password fields from returned XML to not complicate things (can be done later if needed)
	json.NewEncoder(w).Encode(browsers.Browsers)
}

func postOnly(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			reply(w, errMsg("method not allowed"), http.StatusMethodNotAllowed)
			return
		}
		handler(w, r)
	}
}

func withCloseNotifier(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithCancel(r.Context())
		go func() {
			handler(w, r.WithContext(ctx))
			cancel()
		}()
		select {
		case <-w.(http.CloseNotifier).CloseNotify():
			cancel()
		case <-ctx.Done():
		}
	}
}

func readConfig(fn string, browsers *Browsers) error {
	file, err := ioutil.ReadFile(fn)
	if err != nil {
		return fmt.Errorf("error reading configuration file %s: %v", fn, err)
	}
	if err := xml.Unmarshal(file, browsers); err != nil {
		return fmt.Errorf("error parsing configuration file %s: %v", fn, err)
	}
	return nil
}

func appendRoutes(routes Routes, config *Browsers) Routes {
	for _, b := range config.Browsers {
		for _, v := range b.Versions {
			for _, r := range v.Regions {
				for i, h := range r.Hosts {
					host := r.Hosts[i]
					host.region = r.Name
					host.vncInfo = createVNCInfo(host)
					routes[h.sum()] = &host
				}
			}
		}
	}
	return routes
}

func createVNCInfo(h Host) *vncInfo {
	vncURL := h.VNC
	if vncURL != "" {
		u, err := url.Parse(vncURL)
		if err != nil {
			log.Printf("[-] [-] [-] [INVALID_HOST_VNC_URL] [-] [-] [%s] [%s] [-] [-] [-]\n", vncURL, fmt.Sprintf("%s:%d", h.Name, h.Port))
			return nil
		}
		if u.Scheme != vncScheme && u.Scheme != wsScheme {
			log.Printf("[-] [-] [-] [UNSUPPORTED_HOST_VNC_SCHEME] [-] [-] [%s] [%s] [-] [-] [-]\n", vncURL, fmt.Sprintf("%s:%d", h.Name, h.Port))
			return nil
		}
		vncInfo := vncInfo{
			Scheme: u.Scheme,
			Path:   u.Path,
		}
		vncInfo.Scheme = u.Scheme
		vncInfo.Host, vncInfo.Port, _ = net.SplitHostPort(u.Host)
		return &vncInfo
	}
	return nil
}

func requireBasicAuth(authenticator *auth.BasicAuth, handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return authenticator.Wrap(func(w http.ResponseWriter, r *auth.AuthenticatedRequest) {
		handler(w, &r.Request)
	})
}

//WithSuitableAuthentication handles basic authentication and guest quota processing
func WithSuitableAuthentication(authenticator *auth.BasicAuth, handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if !guestAccessAllowed {
			//All requests require authentication
			requireBasicAuth(authenticator, handler)(w, r)
		} else if _, _, basicAuthPresent := r.BasicAuth(); !basicAuthPresent {
			//Run the handler as unauthenticated user
			confLock.RLock()
			_, ok := quota[guestUserName]
			confLock.RUnlock()
			if !ok {
				reply(w, errMsg("Guest access is unavailable."), http.StatusUnauthorized)
			} else {
				handler(w, r)
			}
		} else {
			//Run the handler using basic authentication
			requireBasicAuth(authenticator, handler)(w, r)
		}
	}
}

func vnc(wsconn *websocket.Conn) {
	defer wsconn.Close()
	confLock.RLock()
	defer confLock.RUnlock()

	id := serial()
	head := len(vncPath)
	tail := head + md5SumLength
	path := wsconn.Request().URL.Path
	if len(path) < tail {
		log.Printf("[-] [%d] [-] [INVALID_VNC_REQUEST_URL] [-] [-] [%s] [-] [-] [-] [-]\n", id, path)
		return
	}
	sum := path[head:tail]
	h, ok := routes[sum]
	if ok {
		vncInfo := h.vncInfo
		scheme := vncScheme
		host := h.Name
		port := defaultVNCPort
		path := ""
		if vncInfo != nil {
			scheme = vncInfo.Scheme
			host = vncInfo.Host
			port = vncInfo.Port
			path = vncInfo.Path
		}
		sessionID := strings.Split(wsconn.Request().URL.Path, "/")[2][md5SumLength:]
		switch scheme {
		case vncScheme:
			proxyVNC(id, wsconn, sessionID, host, port)
		case wsScheme:
			proxyWebSockets(id, wsconn, sessionID, host, port, path)
		default:
			{
				log.Printf("[-] [%d] [-] [UNSUPPORTED_HOST_VNC_SCHEME] [-] [-] [%s] [-] [-] [-] [-]\n", id, scheme)
				return
			}
		}
	} else {
		log.Printf("[-] [%d] [-] [UNKNOWN_VNC_HOST] [-] [-] [-] [-] [%s] [-] [-]\n", id, sum)
	}

}

func proxyVNC(id uint64, wsconn *websocket.Conn, sessionID string, host string, port string) {
	var d net.Dialer
	address := fmt.Sprintf("%s:%s", host, port)
	conn, err := d.DialContext(wsconn.Request().Context(), "tcp", address)
	proxyConn(id, wsconn, conn, err, sessionID, address)
}

func proxyWebSockets(id uint64, wsconn *websocket.Conn, sessionID string, host string, port string, path string) {
	origin := "http://localhost/"
	u := fmt.Sprintf("ws://%s:%s%s/%s", host, port, path, sessionID)
	//TODO: consider context from wsconn
	conn, err := websocket.Dial(u, "", origin)
	proxyConn(id, wsconn, conn, err, sessionID, u)
}

func proxyConn(id uint64, wsconn *websocket.Conn, conn net.Conn, err error, sessionID string, address string) {
	log.Printf("[-] [%d] [-] [PROXYING_TO_VNC] [-] [-] [-] [%s] [%s] [-] [-]\n", id, address, sessionID)
	if err != nil {
		log.Printf("[-] [%d] [-] [VNC_ERROR] [-] [-] [-] [%s] [%s] [-] [%v]\n", id, sessionID, address, err)
		return
	}
	defer conn.Close()
	wsconn.PayloadType = websocket.BinaryFrame
	go func() {
		io.Copy(wsconn, conn)
		wsconn.Close()
		log.Printf("[-] [%d] [-] [VNC_SESSION_CLOSED] [-] [-] [-] [%s] [%s] [-] [-]\n", id, address, sessionID)
	}()
	io.Copy(conn, wsconn)
	log.Printf("[-] [%d] [-] [VNC_CLIENT_DISCONNECTED] [-] [-] [-] [%s] [%s] [-] [-]\n", id, address, sessionID)
}

func video(w http.ResponseWriter, r *http.Request) {
	confLock.RLock()
	defer confLock.RUnlock()

	id := serial()
	user, remote := info(r)
	head := len(videoPath)
	tail := head + md5SumLength
	path := r.URL.Path
	if len(path) < tail {
		log.Printf("[-] [%d] [-] [INVALID_VIDEO_REQUEST_URL] [%s] [%s] [%s] [-] [-] [-] [-]\n", id, user, remote, path)
		reply(w, errMsg("invalid video request URL"), http.StatusNotFound)
		return
	}
	sum := path[head:tail]
	sessionID := path[tail:]
	h, ok := routes[sum]
	if ok {
		(&httputil.ReverseProxy{Director: func(r *http.Request) {
			r.URL.Scheme = "http"
			r.URL.Host = h.net()
			r.URL.Path = fmt.Sprintf("/video/%s.mp4", sessionID)
			log.Printf("[-] [%d] [-] [PROXYING_VIDEO] [%s] [%s] [%s] [-] [%s] [-] [-]\n", id, user, remote, r.URL, sessionID)
		}}).ServeHTTP(w, r)
	} else {
		log.Printf("[-] [%d] [-] [UNKNOWN_VIDEO_HOST] [%s] [%s] [-] [-] [%s] [-] [-]\n", id, user, remote, sum)
		reply(w, errMsg("unknown video host"), http.StatusNotFound)
	}
}

func mux() http.Handler {
	mux := http.NewServeMux()
	authenticator := auth.NewBasicAuthenticator(
		"Selenium Grid Router",
		auth.HtpasswdFileProvider(users),
	)
	mux.HandleFunc(pingPath, ping)
	mux.HandleFunc(errPath, err)
	mux.HandleFunc(hostPath, WithSuitableAuthentication(authenticator, host))
	mux.HandleFunc(quotaPath, WithSuitableAuthentication(authenticator, quotaInfo))
	mux.HandleFunc(routePath, withCloseNotifier(WithSuitableAuthentication(authenticator, postOnly(route))))
	mux.Handle(proxyPath, &httputil.ReverseProxy{Director: proxy})
	mux.Handle(vncPath, websocket.Handler(vnc))
	mux.HandleFunc(videoPath, WithSuitableAuthentication(authenticator, video))
	return mux
}
