#!/usr/bin/env bash

set -e

docker build -t $GITHUB_REPOSITORY .
docker tag $GITHUB_REPOSITORY $GITHUB_REPOSITORY:$1
docker tag $GITHUB_REPOSITORY aandryashin/ggr:$1
mkdir -p watch
cp ggr-watch watch/ggr
cp Dockerfile watch/Dockerfile
docker build -t aandryashin/ggr:watch-$1 watch
docker login -u="$DOCKER_USERNAME" -p="$DOCKER_PASSWORD"
docker push $GITHUB_REPOSITORY
docker push $GITHUB_REPOSITORY:$1
docker push aandryashin/ggr:$1
docker push aandryashin/ggr:watch-$1
