#!/bin/bash

check_install_local() {
    if [ "$1" = "-y" ]; then
        use_local=true
        return
    fi
    read -r -p "Install redsnif local dependency from local? [y/N] " response
    case $response in
        [yY][eE][sS]|[yY])
            use_local=true
            ;;
        *)
            use_local=false
            ;;
    esac
}

install_remote_dep() {
    go get -u -v github.com/google/gopacket
    go get -u -v github.com/xiam/resp
    go get -u -v github.com/koding/multiconfig
    go get -u -v github.com/Sirupsen/logrus
}

install_local_dep() {
    if [ "$TRAVIS" = true ]; then
        cd $HOME/gopath/src/github.com/amyangfei/redsnif/rsniffer
        go install
        cd ${TRAVIS_BUILD_DIR}
    elif [ "$use_local" = true ]; then
        cur=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
        bash +x $cur/dev_deps_update.sh
    else
        go get -u -v github.com/amyangfei/redsnif/rsniffer
    fi
}

check_install_local $*
install_remote_dep $*
install_local_dep $*
