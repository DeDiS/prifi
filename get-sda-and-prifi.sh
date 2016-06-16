#!/bin/bash

if [ -z "$GOPATH" ]; then 
	echo "Error: GOPATH is unset."
	exit
fi
mkdir -p "$GOPATH/src/github.com/dedis"
cd "$GOPATH/src/github.com/dedis"

if [ ! -d "cothority" ]; then
	echo "Cloning github.com/dedis/cothority in your GOPATH"
	git clone https://github.com/dedis/cothority.git
fi
cd "cothority"
git checkout prifi
branch=$(git rev-parse --abbrev-ref HEAD)

if [ $branch = "prifi" ]; then
	echo "Successfully checkout out branch PriFi, pulling..."
	git pull
else
	echo "Could not checkout branch PriFi, please do it manually"
fi

prifidev="$GOPATH/src/lbarman/prifi/"
if [ -d "$prifidev" ]; then
	echo "$prifidev seems correctly setup"
else
	echo "Careful, you did not create $prifidev. You will not be able to run"
fi
