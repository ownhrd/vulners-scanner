#!/bin/bash
# Igor Sidorenko
dir=/root/vulners-scanner/
wget "https://vulners.com/api/v3/archive/distributive/?os=centos&version=7" -O centos_7.zip && unzip -d $dir -o centos_7.zip && rm -f centos_7.zip
wget "https://vulners.com/api/v3/archive/distributive/?os=centos&version=6" -O centos_6.zip && unzip -d $dir -o centos_6.zip && rm -f centos_6.zip
wget "https://vulners.com/api/v3/archive/distributive/?os=ubuntu&version=16.04" -O ubuntu_16.04.zip && unzip -d $dir -o ubuntu_16.04.zip && rm -f ubuntu_16.04.zip
wget "https://vulners.com/api/v3/archive/distributive/?os=ubuntu&version=14.04" -O ubuntu_14.04.zip && unzip -d $dir -o ubuntu_14.04.zip && rm -f ubuntu_14.04.zip
wget "https://vulners.com/api/v3/archive/distributive/?os=debian&version=8" -O debian_8.zip && unzip -d $dir -o debian_8.zip && rm -f debian_8.zip
