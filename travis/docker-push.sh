#!/usr/bin/env bash

set -e

docker build -t $TRAVIS_REPO_SLUG .
docker tag $TRAVIS_REPO_SLUG $TRAVIS_REPO_SLUG:$1
docker tag $TRAVIS_REPO_SLUG aandryashin/ggr:$1
mkdir -p watch
cp ggr-watch watch/ggr
cp Dockerfile watch/Dockerfile
docker build -t aandryashin/ggr:watch-$1 watch
docker login -u="$DOCKER_USERNAME" -p="$DOCKER_PASSWORD"
docker push $TRAVIS_REPO_SLUG
docker push $TRAVIS_REPO_SLUG:$1
docker push aandryashin/ggr:$1
docker push aandryashin/ggr:watch-$1