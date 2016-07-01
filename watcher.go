package main

import (
	"time"

	"github.com/fsnotify/fsnotify"
)

func watch(w *fsnotify.Watcher, t time.Duration, f func()) {
	go func() {
		cancel := make(chan bool, 1)
		canceled := make(chan bool, 1)
		triggered := false
		for {
			select {
			case e := <-w.Events:
				if e.Op != 0 {
					if triggered {
						cancel <- true
						<-canceled
					}
					go func() {
						select {
						case <-time.After(t):
							triggered = false
							f()
						case <-cancel:
							canceled <- true
						}
					}()
					triggered = true
				}
			}
		}
	}()
}
