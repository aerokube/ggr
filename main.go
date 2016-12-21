package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/facebookgo/grace/gracehttp"
)

var (
	port     int
	quotaDir string
	users    string
	listen   string
)

func loadQuotaFiles(quotaDir string) error {
	log.Printf("Loading configuration files from [%s]\n", quotaDir)

	glob := fmt.Sprintf("%s%c%s", quotaDir, filepath.Separator, "*.xml")
	files, _ := filepath.Glob(glob)
	if len(files) == 0 {
		return errors.New(fmt.Sprintf("no quota XML files found in [%s] - exiting\n", quotaDir))
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
}

func main() {
	gracehttp.Serve([]*http.Server{
		&http.Server{Addr: listen, Handler: mux()},
	}...)
}