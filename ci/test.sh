#!/bin/bash

export GO111MODULE="on"
go test -tags 'watch' -v -race -coverprofile=coverage.txt -covermode=atomic -coverpkg github.com/aerokube/ggr
