#!/bin/bash

VERSION=v1.46.6-opt
ARCH=`uname -m`
RELEASE=`date "+%Y%m%d%H%M%S"`

if [[ ! -d build ]];then
    echo "create build directory ..."
    mkdir build
else
    echo "clean bulid directory ..."
    rm -rf build/*
fi

echo "build ..."
cd build
../configure --enable-elf-shlibs CFLAGS="-fPIC -O3" CXXFLAGS="-fPIC -O3" --prefix=`pwd`/${VERSION}
make -j
sudo make install

mkdir libext2fs libext2fs/include libext2fs/lib
cp -r ${VERSION}/include/ext2fs libext2fs/include
cp -P ${VERSION}/lib/libext2fs.so* libext2fs/lib
if [[ ${ARCH} == "aarch64" ]];then
    tar -zcf libext2fs.${ARCH}.tar.gz libext2fs
else
    tar -zcf libext2fs.tar.gz libext2fs
fi

echo "done"