#!/bin/bash

# install dependcies for local developing

cur=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
src_dst=$GOPATH/src/github.com/amyangfei/redsnif

rm -rf $src_dst
mkdir -p $src_dst
cp -r $cur/.. $src_dst

cd $src_dst/rsniffer
echo "installing redsnif/rsniffer"
go install

cd $src_dst/datahub
echo "installing redsnif/datahub"
go install

echo "done!"
