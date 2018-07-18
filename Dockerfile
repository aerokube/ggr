FROM alpine:3.8

RUN apk add -U tzdata && rm -Rf /var/cache/apk/*
COPY ggr /usr/bin

EXPOSE 4444
ENTRYPOINT ["/usr/bin/ggr", "-listen", ":4444", "-users", "/etc/grid-router/users.htpasswd", "-quotaDir", "/etc/grid-router/quota"]
