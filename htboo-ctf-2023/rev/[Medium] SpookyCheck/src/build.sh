#!/bin/sh

docker run -v "${PWD}:/mnt" python:3.11 /bin/sh -c 'cd /mnt && python3 -m py_compile check.py && mv __pycache__/*.pyc check.pyc && rm -rf __pycache__'
