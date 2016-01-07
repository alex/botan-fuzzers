#!/bin/sh

if [ ! -f botan ]
then
    git clone https://github.com/randombit/botan.git
fi

cd botan
git checkout .
patch -p1 < ../neuter_crypto.patch

CFG_FLAGS="--with-debug-info --minimized-build --enable-modules=tls,chacha20poly1305,ocb,ccm,system_rng"

CLANG_COV_FLAGS="-fsanitize=address,undefined -fsanitize-coverage=edge,indirect-calls,8bit-counters -fno-sanitize-recover=undefined"

# Just need the static lib, not CLI or tests

./configure.py $CFG_FLAGS --with-build-dir=llvm --cc=clang "--cc-abi-flags=$CLANG_COV_FLAGS"
make -f llvm/Makefile llvm/libbotan-1.11.a -j2

./configure.py $CFG_FLAGS --with-build-dir=afl --cc=gcc --cc-bin=afl-g++
make -f afl/Makefile afl/libbotan-1.11.a -j2
