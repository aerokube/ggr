FROM alpine:3.5
MAINTAINER Ivan Krutov <vania-pooh@vania-pooh.com>

COPY ggr /usr/bin

EXPOSE 4444
ENTRYPOINT ["/usr/bin/ggr", "-port", "4444", "-users", "/etc/grid-router/users.htpasswd", "-quotaDir", "/etc/grid-router/quota"]
