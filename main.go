package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"context"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var (
	listen         string
	quotaDir       string
	users          string
	timeout        time.Duration
	gracefulPeriod time.Duration

	startTime      = time.Now()
	lastReloadTime = time.Now()

	version     bool
	gitRevision string = "HEAD"
	buildStamp  string = "unknown"
)

func loadQuotaFiles(quotaDir string) error {
	log.Printf("Loading configuration files from [%s]\n", quotaDir)

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
	updateQuota(quotaName, browsers)
	log.Printf("Loaded configuration from [%s]:\n%v\n", file, browsers)
}

func updateQuota(quotaName string, browsers Browsers) {
	confLock.Lock()
	defer confLock.Unlock()
	quota[quotaName] = browsers
	routes = appendRoutes(routes, &browsers)
	lastReloadTime = time.Now()
}

func showVersion() {
	fmt.Printf("Git Revision: %s\n", gitRevision)
	fmt.Printf("UTC Build Time: %s\n", buildStamp)
}

func init() {
	flag.StringVar(&listen, "listen", ":4444", "host and port to listen to")
	flag.StringVar(&quotaDir, "quotaDir", "quota", "quota directory")
	flag.StringVar(&users, "users", ".htpasswd", "htpasswd auth file path")
	flag.DurationVar(&timeout, "timeout", 300*time.Second, "session creation timeout in time.Duration format, e.g. 300s or 500ms")
	flag.DurationVar(&gracefulPeriod, "graceful-period", 300*time.Second, "graceful shutdown period in time.Duration format, e.g. 300s or 500ms")
	flag.BoolVar(&version, "version", false, "show version and exit")
	flag.Parse()
	if version {
		showVersion()
		os.Exit(0)
	}
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
	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	server := &http.Server{
		Addr:    listen,
		Handler: mux(),
	}
	go log.Fatal(server.ListenAndServe())

	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), gracefulPeriod)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("graceful shutdown: %v\n", err)
	}
}
