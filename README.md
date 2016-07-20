# Go Grid Router Implementation
[![Build Status](https://travis-ci.org/aandryashin/ggr.svg?branch=master)](https://travis-ci.org/aandryashin/ggr)
[![Coverage](https://codecov.io/github/aandryashin/ggr/coverage.svg)](https://codecov.io/gh/aandryashin/ggr)
[![Release](https://img.shields.io/github/release/aandryashin/ggr.svg)](https://github.com/aandryashin/ggr/releases/latest)

This repository contains a [Go](http://golang.org/) implementation of original [Gridrouter](http://github.com/seleniumkit/gridrouter) code.

## Building
We use [godep](https://github.com/tools/godep) for dependencies management so ensure it's installed before proceeding with next steps. To build the code:

1. Checkout this source tree: ```$ git clone https://github.com/aandryashin/ggr.git```
2. Download dependencies: ```$ godep restore```
3. Build as usually: ```$ go build```
4. Run compiled binary: ```$GOPATH/bin/ggr```

## Running
To run Gridrouter type: ```$ ggr -port 4444 -conf /path/to/browsers.xml```. See [example browsers.xml](https://github.com/aandryashin/ggr/blob/master/quota/browsers.xml). 
