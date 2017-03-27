/*
Go Grid Router (aka ggr) is a lightweight proxy that routes and proxies Selenium Webdriver requests to multiple Selenium hubs.

Usage

To use Go Grid Router do the following:

1) Install Docker to host

2) Create configuration directory:
  $ mkdir -p /etc/grid-router/quota
3) Create users.htpasswd file:
  $ htpasswd -bc /path/to/new.htpasswd test test-password
4) Start Selenium standalone server on port 4445:
  $ java -jar selenium-server-standalone.jar -port 4445
5) Create quota file (use correct browser name and version):
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

6) Start ggr container:
  # docker run -d --name ggr -v /etc/grid-router/:/etc/grid-router:ro --net host aandryashin/ggr:1.1.0
7) Access ggr on port 4444 in the same way you do for Selenium Hub but using the following url: http://test:test-password@localhost:4444/wd/hub

Building

See https://github.com/aandryashin/ggr.
*/
package main
