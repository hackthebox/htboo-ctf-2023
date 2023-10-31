#!/bin/sh
docker build --tag=claw_machine .
docker run -it -p 1337:1337 --rm --name=claw_machine claw_machine