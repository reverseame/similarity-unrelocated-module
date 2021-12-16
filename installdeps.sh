#!/bin/bash

# Dependencies
systemdeps="python python-dev python-pip git multiarch-support build-essential libffi-dev libfuzzy-dev"

pythondeps="pycrypto distorm3 pefile==2019.4.18 ssdeep fuzzyhashlib capstone"

# Install system dependencies
apt-get install -y $systemdeps

# Install libcrypto.so.1.0.0 from a official repository
wget https://deb.debian.org/debian/pool/main/o/openssl/libssl1.0.0_1.0.1t-1+deb8u8_amd64.deb
dpkg -i libssl1.0.0_1.0.1t-1+deb8u8_amd64.deb
rm libssl1.0.0_1.0.1t-1+deb8u8_amd64.deb

# Update setuptools
pip install --upgrade setuptools

# Install python dependencies
pip2 install $pythondeps

# Marked Pefile
if [ ! "$(ls -A marked_pefile)" ]; then
    sudo -u $SUDO_USER git clone --depth 1 --recurse-submodules --shallow-submodules https://github.com/miguelmartinperez/markedPefile.git marked_pefile
fi

