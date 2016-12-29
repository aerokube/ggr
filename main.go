package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/facebookgo/grace/gracehttp"
	"os"
	"os/signal"
	"syscall"
)

var (
	port     int
	quotaDir string
	users    string
	listen   string
)

func loadQuotaFiles(quotaDir string) error {
	log.Printf("Loading configuration files from [%s]\n", quotaDir)

	confLock.Lock()
	defer confLock.Unlock()
	glob := fmt.Sprintf("%s%c%s", quotaDir, filepath.Separator, "*.xml")
	files, _ := filepath.Glob(glob)
	if len(files) == 0 {
		return fmt.Errorf("no quota XML files found in [%s] - exiting", quotaDir)
	}

	for _, file := range files {
		loadQuotaFile(file)
	}
	return nil
}

func loadQuotaFile(file string) {
	fileName := filepath.Base(file)
	quotaName := strings.TrimSuffix(fileName, filepath.Ext(fileName))
	var browsers Browsers
	err := readConfig(file, &browsers)
	if err != nil {
		log.Printf("Failed to load configuration from [%s]: %v", fileName, err)
		return
	}
	quota[quotaName] = browsers
	routes = appendRoutes(routes, &browsers)
	log.Printf("Loaded configuration from [%s]:\n%v\n", file, browsers)
}

func init() {
	flag.IntVar(&port, "port", 4444, "port to bind to")
	flag.StringVar(&quotaDir, "quotaDir", "quota", "quota directory")
	flag.StringVar(&users, "users", ".htpasswd", "htpasswd auth file path")
	flag.Parse()
	listen = fmt.Sprintf(":%d", port)
	log.Printf("Users file is [%s]\n", users)
	if err := loadQuotaFiles(quotaDir); err != nil {
		log.Fatalf("%v\n", err)
	}
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGHUP)
	go func() {
		for {
			<-sig
			loadQuotaFiles(quotaDir)
		}
	}()
}

func main() {
	gracehttp.Serve([]*http.Server{
		{Addr: listen, Handler: mux()},
	}...)
}
