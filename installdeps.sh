#!/bin/bash

# Dependencies
systemdeps="python2.7 python2.7-dev python-pip ssdeep libfuzzy-dev git cmake libffi-dev libssl1.0.0 build-essential"
pythondeps="pycrypto distorm3 pefile ssdeep fuzzyhashlib capstone"


# Install system dependencies
apt-get install -y $systemdeps

# Install python dependencies
pip2 install $pythondeps

# Marked Pefile
sudo -u $SUDO_USER git clone git@github.com:miguelmartinperez/markedPefile.git marked_pefile
cd marked_pefile
sudo -u $SUDO_USER sh installdeps.sh
cd ..

