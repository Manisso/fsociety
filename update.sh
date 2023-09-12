#!/bin/bash
# Script for update Fsociety tools

git clone --depth=1 https://github.com/coolst3r/fsociety-pull.git
sudo chmod +x fsociety/install.sh
./fsociety/install.sh
