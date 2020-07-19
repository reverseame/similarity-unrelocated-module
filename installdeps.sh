#!/bin/bash

# Dependencies
systemdeps="python2.7 python2.7-dev python-pip ssdeep libfuzzy-dev git cmake libffi-dev libssl1.0.0 build-essential"
pythondeps="pycrypto distorm3 pefile ssdeep fuzzyhashlib capstone"

# Add jessie-backports repository
cp jessie-backports.list /etc/apt/sources.list.d
apt-get update

# Install system dependencies
apt-get install -y $systemdeps

# Install python dependencies
pip2 install $pythondeps

# Install TLSH
git clone "https://github.com/trendmicro/tlsh.git" /tmp/tlsh/
oldpwd=$(pwd)
cd /tmp/tlsh/
./make.sh
cd py_ext
python2 setup.py build
python2 setup.py install
cd $oldpwd
rm -rf /tmp/tlsh/