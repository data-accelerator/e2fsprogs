#!/bin/bash

VERSION=${1:-"v1.47.0-opt"}
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
../configure --enable-elf-shlibs --disable-debugfs --disable-imager --disable-resizer --disable-defrag \
    --disable-uuidd --disable-fuse2fs --disable-fsck --disable-e2initrd-helper \
    CFLAGS="-fPIC -O3" CXXFLAGS="-fPIC -O3" --prefix=`pwd`/${VERSION}
make -j8
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