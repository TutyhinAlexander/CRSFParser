#!/bin/bash 
#This script will install CRSFParser library

#build
clear
sudo rm -rf build
mkdir build 
cd build
$echo pwd
echo "prepare make configs..."
# $1 can be -DRELEASE=ON
cmake $1 ..
echo "build CRSFParser project..."
make
echo "install CRSFParser library..."
sudo make install

echo "build examples..."
cd ../examples
sudo rm -rf build
mkdir build
cd build
$echo pwd
cmake ..
make
