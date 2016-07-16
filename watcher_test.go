package main

import (
	"testing"
	"time"

	. "github.com/aandryashin/matchers"
	"github.com/fsnotify/fsnotify"
)

func TestTimerShouldTrigger(t *testing.T) {
	watcher, _ := fsnotify.NewWatcher()
	defer watcher.Close()

	ch := make(chan bool)
	watch(watcher, 200*time.Millisecond, func() {
		ch <- true
	})
	call := false

	watcher.Events <- fsnotify.Event{Op: fsnotify.Create}
	select {
	case <-time.After(100 * time.Millisecond):
	case call = <-ch:
	}
	AssertThat(t, call, Is{false})
}

func TestTimerShouldNotTrigger(t *testing.T) {
	watcher, _ := fsnotify.NewWatcher()
	defer watcher.Close()

	ch := make(chan bool)
	watch(watcher, 100*time.Millisecond, func() {
		ch <- true
	})
	call := false

	watcher.Events <- fsnotify.Event{Op: fsnotify.Create}
	select {
	case <-time.After(200 * time.Millisecond):
	case call = <-ch:
	}
	AssertThat(t, call, Is{true})
}

func TestTimerShouldTriggerOnce(t *testing.T) {
	watcher, _ := fsnotify.NewWatcher()
	defer watcher.Close()

	ch := make(chan bool)
	watch(watcher, 300*time.Millisecond, func() {
		ch <- true
	})
	call := false

	watcher.Events <- fsnotify.Event{Op: fsnotify.Create}
	select {
	case <-time.After(200 * time.Millisecond):
	case call = <-ch:
	}
	AssertThat(t, call, Is{false})

	watcher.Events <- fsnotify.Event{Op: fsnotify.Create}
	select {
	case <-time.After(200 * time.Millisecond):
	case call = <-ch:
	}
	AssertThat(t, call, Is{false})

	select {
	case <-time.After(200 * time.Millisecond):
	case call = <-ch:
	}
	AssertThat(t, call, Is{true})
}
