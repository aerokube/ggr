package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"context"

	"github.com/abbot/go-http-auth"
	"golang.org/x/net/websocket"
	"io"
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

func (c *caps) capability(k string) string {
	dc := (*c)["desiredCapabilities"]
	switch dc.(type) {
	case map[string]interface{}:
		v := dc.(map[string]interface{})
		switch v[k].(type) {
		case string:
			return v[k].(string)
		}
	}
	return ""
}

func (c *caps) setCapability(k string, v string) {
	(*c)["desiredCapabilities"].(map[string]interface{})[k] = v
}

func (c *caps) browser() string {
	browserName := c.capability("browserName")
	if browserName != "" {
		return browserName
	}
	return c.capability("deviceName")
}

func (c *caps) version() string {
	return c.capability("version")
}

func (c *caps) setVersion(version string) {
	c.setCapability("version", version)
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
	if err != nil {
		reply(w, errMsg(fmt.Sprintf("bad json format: %s", err.Error())), http.StatusBadRequest)
		log.Printf("[%d] [BAD_JSON] [%s] [%s] [%v]\n", id, user, remote, err)
		return
	}
	browser, version := c.browser(), c.version()
	if browser == "" {
		reply(w, errMsg("browser not set"), http.StatusBadRequest)
		log.Printf("[%d] [BROWSER_NOT_SET] [%s] [%s]\n", id, user, remote)
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
		log.Printf("[%d] [UNSUPPORTED_BROWSER] [%s] [%s] [%s]\n", id, user, remote, fmtBrowser(browser, version))
		return
	}
	lastHostError := ""
loop:
	for h, i := hosts.choose(); ; h, i = hosts.choose() {
		count++
		if h == nil {
			break loop
		}
		log.Printf("[%d] [SESSION_ATTEMPTED] [%s] [%s] [%s] [%s] [%d]\n", id, user, remote, fmtBrowser(browser, version), h.net(), count)
		c.setVersion(version)
		resp, status := h.session(r.Context(), r.Header, c)
		select {
		case <-r.Context().Done():
			log.Printf("[%d] [%.2fs] [CLIENT_DISCONNECTED] [%s] [%s] [%s] [%s] [%d]\n", id, float64(time.Now().Sub(start).Seconds()), user, remote, fmtBrowser(browser, version), h.net(), count)
			return
		default:
		}
		switch status {
		case browserStarted:
			sess, ok := resp["sessionId"].(string)
			if !ok {
				protocolError := func() {
					reply(w, errMsg("protocol error"), http.StatusBadGateway)
					log.Printf("[%d] [BAD_RESPONSE] [%s] [%s] [%s] [%s]\n", id, user, remote, fmtBrowser(browser, version), h.net())
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
			log.Printf("[%d] [%.2fs] [SESSION_CREATED] [%s] [%s] [%s] [%s] [%s] [%d]\n", id, float64(time.Now().Sub(start).Seconds()), user, remote, fmtBrowser(browser, version), h.net(), sess, count)
			return
		case browserFailed:
			hosts = append(hosts[:i], hosts[i+1:]...)
		case seleniumError:
			excludedHosts.add(h.net())
			excludedRegions.add(h.region)
			hosts, version, excludedRegions = browsers.find(browser, version, excludedHosts, excludedRegions)
		}
		errMsg := browserErrMsg(resp)
		log.Printf("[%d] [SESSION_FAILED] [%s] [%s] [%s] [%s] %s\n", id, user, remote, fmtBrowser(browser, version), h.net(), errMsg)
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
	log.Printf("[%d] [SESSION_NOT_CREATED] [%s] [%s] [%s]\n", id, user, remote, fmtBrowser(browser, version))
}

func proxy(r *http.Request) {
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
			r.URL.Host = h.net()
			r.URL.Path = proxyPath
			fragments := strings.Split(proxyPath, "/")
			if r.Method == "DELETE" && len(fragments) == sessPart+1 {
				sess := fragments[sessPart]
				log.Printf("[SESSION_DELETED] [%s] [%s] [%s]\n", remote, h.net(), sess)
			}
			return
		}
		log.Printf("[ROUTE_NOT_FOUND] [%s] [%s]\n", remote, proxyPath)
	} else {
		log.Printf("[INVALID_URL] [%s] [%s]\n", remote, r.URL.Path)
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
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Host{Name: h.Name, Port: h.Port, Count: h.Count})
}

func quotaInfo(w http.ResponseWriter, r *http.Request) {
	confLock.RLock()
	defer confLock.RUnlock()
	id := serial()
	user, remote := info(r)
	log.Printf("[%d] [QUOTA_INFO_REQUESTED] [%s] [%s]\n", id, user, remote)
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
	vncUrl := h.VNC
	if vncUrl != "" {
		u, err := url.Parse(vncUrl)
		if err != nil {
			log.Printf("[INVALID_HOST_VNC_URL] [%s] [%s]\n", fmt.Sprintf("%s:%s", h.Name, h.Port), vncUrl)
			return nil
		}
		if u.Scheme != vncScheme && u.Scheme != wsScheme {
			log.Printf("[UNSUPPORTED_HOST_VNC_SCHEME] [%s] [%s]\n", fmt.Sprintf("%s:%s", h.Name, h.Port), vncUrl)
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
	head := len(vncPath)
	tail := head + md5SumLength
	path := wsconn.Request().URL.Path
	if len(path) < tail {
		log.Printf("[INVALID_VNC_REQUEST_URL] [%s]\n", path)
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
		sessionId := strings.Split(wsconn.Request().URL.Path, "/")[2]
		switch scheme {
		case vncScheme:
			proxyVNC(wsconn, sessionId, host, port)
		case wsScheme:
			proxyWebSockets(wsconn, sessionId, host, port, path)
		default:
			{
				log.Printf("[UNSUPPORTED_HOST_VNC_SCHEME] [%s]\n", scheme)
				return
			}
		}
	} else {
		log.Printf("[UNKNOWN_VNC_HOST] [%s]\n", sum)
	}

}

func proxyVNC(wsconn *websocket.Conn, sessionId string, host string, port string) {
	var d net.Dialer
	address := fmt.Sprintf("%s:%s", host, port)
	conn, err := d.DialContext(wsconn.Request().Context(), "tcp", address)
	proxyConn(wsconn, conn, err, sessionId, address)
}

func proxyWebSockets(wsconn *websocket.Conn, sessionId string, host string, port string, path string) {
	origin := "http://localhost/"
	u := fmt.Sprintf("ws://%s:%s%s/%s", host, port, path, sessionId)
	//TODO: consider context from wsconn
	conn, err := websocket.Dial(u, "", origin)
	proxyConn(wsconn, conn, err, sessionId, u)
}

func proxyConn(wsconn *websocket.Conn, conn net.Conn, err error, sessionId string, address string) {
	log.Printf("[PROXYING_TO_VNC] [%s] [%s]\n", sessionId, address)
	if err != nil {
		log.Printf("[VNC_ERROR] [%s] [%s] [%v]\n", sessionId, address, err)
		return
	}
	defer conn.Close()
	wsconn.PayloadType = websocket.BinaryFrame
	go func() {
		io.Copy(wsconn, conn)
		wsconn.Close()
		log.Printf("[VNC_SESSION_CLOSED] [%s] [%s]\n", sessionId, address)
	}()
	io.Copy(conn, wsconn)
	log.Printf("[VNC_CLIENT_DISCONNECTED] [%s] [%s]\n", sessionId, address)
}

func video(w http.ResponseWriter, r *http.Request) {
	confLock.RLock()
	defer confLock.RUnlock()

	head := len(videoPath)
	tail := head + md5SumLength
	path := r.URL.Path
	if len(path) < tail {
		log.Printf("[INVALID_VIDEO_REQUEST_URL] [%s]\n", path)
		reply(w, errMsg("invalid video request URL"), http.StatusNotFound)
		return
	}
	sum := path[head:tail]
	sessionId := path[tail:]
	h, ok := routes[sum]
	if ok {
		(&httputil.ReverseProxy{Director: func(r *http.Request) {
			r.URL.Scheme = "http"
			r.URL.Host = h.net()
			r.URL.Path = fmt.Sprintf("/video/%s.mp4", sessionId)
			log.Printf("[PROXYING_VIDEO] [%s] [%s]\n", sessionId, r.URL)
		}}).ServeHTTP(w, r)
	} else {
		log.Printf("[UNKNOWN_VIDEO_HOST] [%s]\n", sum)
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
