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
	listen             string
	quotaDir           string
	users              string
	timeout            time.Duration
	gracefulPeriod     time.Duration
	guestAccessAllowed bool
	guestUserName      string
	verbose            bool

	startTime      = time.Now()
	lastReloadTime = time.Now()

	version     bool
	gitRevision = "HEAD"
	buildStamp  = "unknown"
)

func loadQuotaFiles(quotaDir string) error {
	log.Printf("[-] [-] [INIT] [-] [-] [-] [-] [-] [-] [Loading configuration files from \"%s\"]\n", quotaDir)

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
		log.Printf("[-] [-] [INIT] [-] [-] [-] [-] [-] [-] [Failed to load configuration from \"%s\": %v]\n", fileName, err)
		return
	}
	updateQuota(quotaName, browsers)
	if verbose {
		log.Printf("[-] [-] [INIT] [-] [-] [-] [-] [-] [-] [Loaded configuration from \"%s\"]\n%v\n", file, browsers)
	}
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

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return !os.IsNotExist(err)
}

func init() {
	flag.BoolVar(&guestAccessAllowed, "guests-allowed", false, "Allow guest (unauthenticated) users to access the grid")
	flag.StringVar(&guestUserName, "guests-quota", "guest", "Which quota file to use for guests")
	flag.StringVar(&listen, "listen", ":4444", "host and port to listen to")
	flag.StringVar(&quotaDir, "quotaDir", "quota", "quota directory")
	flag.StringVar(&users, "users", ".htpasswd", "htpasswd auth file path")
	flag.DurationVar(&timeout, "timeout", 300*time.Second, "session creation timeout in time.Duration format, e.g. 300s or 500ms")
	flag.DurationVar(&gracefulPeriod, "graceful-period", 300*time.Second, "graceful shutdown period in time.Duration format, e.g. 300s or 500ms")
	flag.BoolVar(&version, "version", false, "show version and exit")
	flag.BoolVar(&verbose, "verbose", false, "enable verbose mode")
	flag.Parse()
	if version {
		showVersion()
		os.Exit(0)
	}
	if !fileExists(users) && !guestAccessAllowed {
		log.Fatalf("[-] [-] [INIT] [-] [-] [-] [-] [-] [-] [Users file \"%s\" does not exist]\n", users)
	}
	log.Printf("[-] [-] [INIT] [-] [-] [-] [-] [-] [-] [Users file is \"%s\"]\n", users)
	if err := loadQuotaFiles(quotaDir); err != nil {
		log.Fatalf("[-] [-] [INIT] [-] [-] [-] [-] [-] [-] [%v]\n", err)
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
	e := make(chan error)
	go func() {
		e <- server.ListenAndServe()
	}()
	select {
	case err := <-e:
		log.Fatalf("[-] [-] [INIT] [-] [-] [-] [-] [-] [-] [%v]\n", err)
	case <-stop:
	}

	log.Printf("[-] [%s] [SHUTTING_DOWN] [-] [-] [-] [-] [-] [-] [-]\n", gracefulPeriod)
	ctx, cancel := context.WithTimeout(context.Background(), gracefulPeriod)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("[-] [-] [SHUTDOWN_FAILURE] [-] [-] [-] [-] [-] [-] [%v]\n", err)
	}
}
