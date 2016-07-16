package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

const (
	browserStarted int = iota
	browserFailed
	seleniumError
)

const (
	pingPath  string = "/ping"
	errPath   string = "/err"
	routePath string = "/wd/hub/session"
	proxyPath string = routePath + "/"
	head      int    = len(proxyPath)
	tail      int    = head + 32
	sessPart  int    = 4 // /wd/hub/session/{various length session}
)

var (
	port     = flag.Int("port", 8080, "port to bind to")
	conf     = flag.String("conf", "quota/browsers.xml", "browsers configuration file path")
	delay    = flag.Int("delay", 10, "delay in seconds before config reloading")
	listen   string
	config   Browsers
	routes   map[string]*Host = make(map[string]*Host)
	num      uint64
	numLock  sync.Mutex
	confLock sync.RWMutex
)

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

func (c *caps) browser() string {
	return c.capability("browserName")
}

func (c *caps) version() string {
	return c.capability("version")
}

func (h *Host) url() string {
	return fmt.Sprintf("http://%s%s", h.net(), routePath)
}

func (h *Host) session(c caps) (map[string]interface{}, int) {
	b, _ := json.Marshal(c)
	resp, err := http.Post(h.url(), "application/json", bytes.NewReader(b))
	if err != nil {
		return nil, seleniumError
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

func reply(w http.ResponseWriter, msg map[string]interface{}) {
	reply, _ := json.Marshal(msg)
	w.Header().Set("Content-Type", "application/json")
	w.Write(reply)
}

func serial() uint64 {
	numLock.Lock()
	defer numLock.Unlock()
	id := num
	num++
	return id
}

func info(r *http.Request) (user, remote string) {
	user = "unknown"
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

func jsonErrMsg(msg string) string {
	message := make(map[string]string)
	message["message"] = msg
	value := make(map[string]interface{})
	value["value"] = message
	value["status"] = 13
	result, _ := json.Marshal(value)
	return string(result)
}

func route(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	id := serial()
	user, remote := info(r)
	var c caps
	err := json.NewDecoder(r.Body).Decode(&c)
	if err != nil {
		http.Error(w, fmt.Sprintf("bad json format: %s", err.Error()), http.StatusBadRequest)
		log.Printf("[%d] [BAD_JSON] [%s] [%s] [%v]\n", id, user, remote, err)
		return
	}
	browser, version := c.browser(), c.version()
	if browser == "" {
		http.Error(w, "browser not set", http.StatusBadRequest)
		log.Printf("[%d] [BROWSER_NOT_SET] [%s] [%s]\n", id, user, remote)
		return
	}
	count := 0
loop:
	for {
		confLock.RLock()
		hosts := config.find(browser, version)
		confLock.RUnlock()
		if len(hosts) == 0 {
			http.Error(w, fmt.Sprintf("unsupported browser: %s", fmtBrowser(browser, version)), http.StatusNotFound)
			log.Printf("[%d] [UNSUPPORTED_BROWSER] [%s] [%s] [%s]\n", id, user, remote, fmtBrowser(browser, version))
			return
		}
		for h, i := hosts.choose(); ; h, i = hosts.choose() {
			count++
			if h == nil {
				break loop
			}
			log.Printf("[%d] [SESSION_ATTEMPTED] [%s] [%s] [%s] [%s] [%d]\n", id, user, remote, fmtBrowser(browser, version), h.net(), count)
			excludes := make([]string, 0)
			resp, status := h.session(c)
			switch status {
			case browserStarted:
				sess := resp["sessionId"].(string)
				resp["sessionId"] = h.sum() + sess
				reply(w, resp)
				log.Printf("[%d] [%.2fs] [SESSION_CREATED] [%s] [%s] [%s] [%s] [%s] [%d]\n", id, float64(time.Now().Sub(start).Seconds()), user, remote, fmtBrowser(browser, version), h.net(), sess, count)
				return
			case browserFailed:
				hosts = append(hosts[:i], hosts[i+1:]...)
			case seleniumError:
				excludes = append(excludes, h.region)
				hosts = config.find(browser, version, excludes...)
			}
			log.Printf("[%d] [SESSION_FAILED] [%s] [%s] [%s] [%s] %s\n", id, user, remote, fmtBrowser(browser, version), h.net(), browserErrMsg(resp))
			if len(hosts) == 0 {
				break loop
			}
		}
	}
	http.Error(w, jsonErrMsg(fmt.Sprintf("cannot create session %s on any hosts after %d attempt(s)", fmtBrowser(browser, version), count)), http.StatusInternalServerError)
	log.Printf("[%d] [SESSION_NOT_CREATED] [%s] [%s] [%s]\n", id, user, remote, fmtBrowser(browser, version))
}

func proxy(r *http.Request) {
	user, remote := info(r)
	r.URL.Scheme = "http"
	if len(r.URL.Path) > tail {
		sum := r.URL.Path[head:tail]
		path := r.URL.Path[:head] + r.URL.Path[tail:]
		if h, ok := routes[sum]; ok {
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
			r.URL.Host = h.net()
			r.URL.Path = path
			if r.Method == "DELETE" {
				sess := strings.Split(path, "/")[sessPart]
				log.Printf("[SESSION_DELETED] [%s] [%s] [%s] [%s]\n", user, remote, h.net(), sess)
			}
			return
		}
	}
	r.URL.Host = listen
	r.URL.Path = errPath
}

func ping(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Ok\n"))
}

func err(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "route not found", http.StatusNotFound)
}

func postOnly(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handler(w, r)
	}
}

func readConfig(fn string, browsers *Browsers) error {
	file, err := ioutil.ReadFile(fn)
	if err != nil {
		return errors.New(fmt.Sprintf("error reading configuration file %s: %v", fn, err))
	}
	if err := xml.Unmarshal(file, browsers); err != nil {
		return errors.New(fmt.Sprintf("error parsing configuration file %s: %v", fn, err))
	}
	return nil
}

func linkRoutes(config *Browsers) map[string]*Host {
	routes := make(map[string]*Host)
	for _, b := range config.Browsers {
		for _, v := range b.Versions {
			for _, r := range v.Regions {
				for i, h := range r.Hosts {
					r.Hosts[i].region = r.Name
					routes[h.sum()] = &r.Hosts[i]
				}
			}
		}
	}
	return routes
}

func watchDir(watcher *fsnotify.Watcher, dir string, delay time.Duration) error {
	watch(watcher, delay, func() {
		log.Printf("Reloading configuration file [%s]\n", *conf)
		var newconf Browsers
		err := readConfig(*conf, &newconf)
		if err != nil {
			log.Println(err)
			return
		}
		newroutes := linkRoutes(&newconf)
		confLock.Lock()
		config, routes = newconf, newroutes
		confLock.Unlock()
		log.Printf("Reloaded configuration from [%s]:\n%v\n", *conf, config)
	})
	if err := watcher.Add(dir); err != nil {
		return errors.New(fmt.Sprintf("cannot watch directory: %s: %v", dir, err))
	}
	return nil
}

func mux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(pingPath, ping)
	mux.HandleFunc(errPath, err)
	mux.HandleFunc(routePath, postOnly(route))
	mux.Handle(proxyPath, &httputil.ReverseProxy{Director: proxy})
	return mux
}

func init() {
	flag.Parse()
	listen = fmt.Sprintf(":%d", *port)

	log.Printf("Loading configuration file [%s]\n", *conf)
	err := readConfig(*conf, &config)
	if err != nil {
		log.Fatal(err)
	}
	routes = linkRoutes(&config)
	log.Printf("Loaded configuration from [%s]:\n%v\n", *conf, config)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("error initializing file system notifications: %v", err)
	}
	watchDir(watcher, path.Dir(*conf), time.Duration(*delay)*time.Second)
}

func main() {
	log.Println("listening on", listen)
	log.Print(http.ListenAndServe(listen, mux()))
}
