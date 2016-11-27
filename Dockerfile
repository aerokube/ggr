FROM ubuntu:16.04
MAINTAINER Ivan Krutov <vania-pooh@vania-pooh.com>

ENV PORT 4444
ENV USERS_FILE /etc/grid-router/users.htpasswd
ENV QUOTA_DIRECTORY /etc/grid-router/quota

COPY ggr /usr/bin
COPY entrypoint.sh /

EXPOSE 4444
ENTRYPOINT /entrypoint.sh
