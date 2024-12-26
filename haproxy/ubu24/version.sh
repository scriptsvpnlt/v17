#!/bin/bash
clear

VersionHaproxy="2.9"
            echo " install haproxy versi ${VersionHaproxy} untuk Ubuntu 24.04"
            sudo add-apt-repository ppa:vbernat/haproxy-${VersionHaproxy} --yes
            sudo apt update
            apt-get install haproxy=${VersionHaproxy}.\* -y
