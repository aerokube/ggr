package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
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
)

var (
	port   = flag.Int("port", 8080, "port to bind to")
	conf   = flag.String("conf", "browsers.xml", "browsers configuration file path")
	listen string
	config Browsers
	routes map[string]*Host = make(map[string]*Host)
)

type caps map[string]interface{}

func (c *caps) capability(k string) string {
	if v, ok := (*c)["desiredCapabilities"].(map[string]interface{})[k].(string); ok {
		return v
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
	if resp.StatusCode != http.StatusOK {
		return nil, browserFailed
	}
	var reply map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&reply)
	return reply, browserStarted
}

func reply(w http.ResponseWriter, msg map[string]interface{}) {
	reply, _ := json.Marshal(msg)
	w.Header().Set("Content-Type", "application/json")
	w.Write(reply)
}

func route(w http.ResponseWriter, r *http.Request) {
	var c caps
	err := json.NewDecoder(r.Body).Decode(&c)
	if err != nil {
		http.Error(w, fmt.Sprintf("bad json format: %s", err.Error()), http.StatusBadRequest)
		return
	}
	browser, version := c.browser(), c.version()
	if browser == "" {
		http.Error(w, "browser not set", http.StatusBadRequest)
		return
	}
loop:
	for {
		hosts := config.find(browser, version)
		if len(hosts) == 0 {
			http.Error(w, fmt.Sprintf("unsupported browser: %s %s", browser, version), http.StatusNotFound)
			return
		}
		excludes := make([]string, 0)
		n := 1
		for h, i := hosts.choose(); ; h, i = hosts.choose() {
			switch resp, status := h.session(c); status {
			case browserStarted:
				sess := resp["sessionId"].(string)
				log.Printf("session %s started on %s in %d attempt", sess, h.net(), n)
				resp["sessionId"] = h.sum() + sess
				reply(w, resp)
				return
			case browserFailed:
				log.Printf("cannot start %s %s on %s", browser, version, h.net())
				hosts = append(hosts[:i], hosts[i+1:]...)
			case seleniumError:
				log.Printf("failed to connect to %s:%d from %s", h.Name, h.Port, h.region)
				excludes = append(excludes, h.region)
				hosts = config.find(browser, version, excludes...)
			}
			if len(hosts) == 0 {
				break loop
			}
			n++
		}
	}
	http.Error(w, fmt.Sprintf("cannot create session %s %s on any hosts", browser, version), http.StatusInternalServerError)
}

func proxy(r *http.Request) {
	r.URL.Scheme = "http"
	if len(r.URL.Path) > tail {
		sum := r.URL.Path[head:tail]

		path := r.URL.Path[:head] + r.URL.Path[tail:]
		sess := path[head : head+36]
		if h, ok := routes[sum]; ok {
			if r.ContentLength > 0 {
				defer r.Body.Close()
				body, _ := ioutil.ReadAll(r.Body)
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
				log.Printf("session %s deleted on %s", sess, h.net())
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
	http.Error(w, "route not found", http.StatusBadRequest)
}

func postOnly(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		handler(w, r)
	}
}

func init() {
	flag.Parse()
	listen = fmt.Sprintf(":%d", *port)

	file, err := ioutil.ReadFile(*conf)
	if err != nil {
		log.Fatal("error reading configuration: ", err)
	}
	if err := xml.Unmarshal(file, &config); err != nil {
		log.Fatal("error parsing configuration: ", err)
	}
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
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc(pingPath, ping)
	mux.HandleFunc(errPath, err)
	mux.HandleFunc(routePath, postOnly(route))
	mux.Handle(proxyPath, &httputil.ReverseProxy{Director: proxy})
	log.Println("listening on", listen)
	log.Print(http.ListenAndServe(listen, mux))
}
