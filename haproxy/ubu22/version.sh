#!/bin/bash
clear

VersionHaproxy="2.4"
            echo " install haproxy versi ${VersionHaproxy} untuk Ubuntu 22.04"
            sudo add-apt-repository ppa:vbernat/haproxy-${VersionHaproxy} --yes
            sudo apt update
            apt-get install haproxy=${VersionHaproxy}.\* -y
