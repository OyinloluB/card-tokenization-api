#!/bin/bash
# deploy.sh

git pull

# build and start containers
docker-compose build
docker-compose up -d

# show logs
docker-compose logs -f