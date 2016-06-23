#!/bin/bash
lvl=3
if [ $# -eq 1 ]
  then
    lvl=$1
fi
echo "Make sure $GOPATH/src/github.com/dedis/cothority is a git repo, on branch prifi"
echo "Make sure $GOPATH/src/github.com/lbarman/prifi_dev is the git repo of prifi"
echo "---"
currentPath=$(pwd)
echo "Running PriFi simulation through SDA, debug level is $lvl, output is in $currentPath/log.txt"
cd $GOPATH/src/github.com/dedis/cothority/simul;
go build
./simul -debug $lvl runfiles/prifi_simple.toml -platform localhost 2>&1 | tee "$currentPath"/log.txt
