#!/bin/bash
# This should be enough
# to keep you from 
# bruteforcing the timestamp
FAKETIME=$(python3 faketime.py) LD_PRELOAD=/usr/local/lib/faketime/libfaketime.so.1 python3 server.py