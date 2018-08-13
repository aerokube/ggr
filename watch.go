// +build watch

package main

import (
	"github.com/aandryashin/reloader"
	"log"
	"time"
)

func init() {

	err := reloader.Watch(quotaDir, func() {
		loadQuotaFiles(quotaDir)
	}, 5*time.Second)
	if err != nil {
		log.Fatalf("[-] [INIT] [Failed to init watching quota for changes: %v]", err)
	}
	log.Printf("[-] [INIT] [Watching quota directory %s for changes]", quotaDir)
}
