#!/bin/bash

# install dependcies for local developing

cur=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
src_dst=$GOPATH/src/github.com/amyangfei/redsnif

rm -rf $src_dst
mkdir -p $src_dst
cp -r $cur/../sniffer $src_dst

cd $src_dst/sniffer
echo "installing redsnif/sniffer"
go install

echo "done!"
