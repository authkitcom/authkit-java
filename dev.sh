#!/bin/bash

set -e

docker-compose build
docker-compose stop || true
docker-compose rm -f || true
docker-compose up -d

