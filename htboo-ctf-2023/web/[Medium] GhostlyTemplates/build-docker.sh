#!/bin/bash
docker rm -f web_ghostlytemplates
docker build -t web_ghostlytemplates .
docker run --name=web_ghostlytemplates --rm -p1337:1337 -it web_ghostlytemplates