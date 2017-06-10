# Go Grid Router
[![Build Status](https://travis-ci.org/aerokube/ggr.svg?branch=master)](https://travis-ci.org/aerokube/ggr)
[![Coverage](https://codecov.io/github/aerokube/ggr/coverage.svg)](https://codecov.io/gh/aerokube/ggr)
[![GoReport](https://goreportcard.com/badge/github.com/aerokube/ggr)](https://goreportcard.com/report/github.com/aerokube/ggr)
[![Release](https://img.shields.io/github/release/aerokube/ggr.svg)](https://github.com/aerokube/ggr/releases/latest)
[![GoDoc](https://godoc.org/github.com/aerokube/ggr?status.svg)](https://godoc.org/github.com/aerokube/ggr)

Go Grid Router (aka Ggr) is a lightweight active load balancer used to create scalable and highly-available [Selenium](http://seleniumhq.org/) clusters.

## Quick Start Guide
To use Go Grid Router do the following:
1) Install [Docker](http://docker.com/) to host
2) Create configuration directory:
```
$ mkdir -p /etc/grid-router/quota
```
3) Create ```users.htpasswd``` file:
```
$ htpasswd -bc /etc/grid-router/users.htpasswd test test-password
```
4) Start Selenium standalone server on port 4445:
```
$ java -jar selenium-server-standalone.jar -port 4445
```
5) Create quota file (use correct browser name and version):
```
$ cat /etc/grid-router/quota/test.xml
<qa:browsers xmlns:qa="urn:config.gridrouter.qatools.ru">
<browser name="firefox" defaultVersion="45.0">
    <version number="45.0">
        <region name="1">
            <host name="localhost" port="4445" count="1"/>
        </region>
    </version>
</browser>
</qa:browsers>
```
***Note***: file name should correspond to user name you added to htpasswd file. For user ```test``` we added on previous steps you should create ```test.xml```.

6) Start Ggr container:
```
# docker run -d --name ggr -v /etc/grid-router/:/etc/grid-router:ro --net host aerokube/ggr:latest-release
```
7) Access Ggr on port 4444 in the same way you do for Selenium Hub but using the following url:
```
http://test:test-password@localhost:4444/wd/hub
```

## Complete Guide & Build Instructions

Complete reference guide (including build instructions) can be found at: http://aerokube.com/ggr/latest/