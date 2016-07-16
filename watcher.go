package main

import (
	"time"

	"github.com/fsnotify/fsnotify"
)

func watch(w *fsnotify.Watcher, t time.Duration, f func()) {
	go func() {
		var cancel chan struct{}
		for {
			select {
			case e := <-w.Events:
				if e.Op != 0 {
					if cancel != nil {
						close(cancel)
					}
					cancel = make(chan struct{})
					go func(cancel chan struct{}) {
						select {
						case <-time.After(t):
							f()
						case <-cancel:
						}
					}(cancel)
				}
			}
		}
	}()
}
