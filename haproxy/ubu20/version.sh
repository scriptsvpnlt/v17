#!/bin/bash
clear

# ubuntu 20.04 Focal Fossa
VersionHaproxy="2.0"
            echo " install haproxy versi ${VersionHaproxy} untuk Ubuntu 20.04"
            add-apt-repository ppa:vbernat/haproxy-${VersionHaproxy} -yes
            sudo apt update
            apt-get install haproxy=${VersionHaproxy}.\* -y
