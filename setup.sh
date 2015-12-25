#!/bin/sh

SNAPSHOT=snapshot-$(date +%Y%m%d).tar.gz
wget https://github.com/randombit/botan/archive/master.tar.gz -O $SNAPSHOT

rm -rf botan-master
tar -xzf $SNAPSHOT

cd botan-master
patch -p1 < ../neuter_crypto.patch

CFG_FLAGS="--with-debug-info --minimized-build --enable-modules=tls,chacha20poly1305,ocb,ccm,system_rng"

CLANG_COV_FLAGS="-fsanitize=address,undefined -fsanitize-coverage=edge,indirect-calls,8bit-counters -fno-sanitize-recover=undefined"

./configure.py $CFG_FLAGS --with-build-dir=llvm --cc=clang "--cc-abi-flags=$CLANG_COV_FLAGS"

./configure.py $CFG_FLAGS --with-build-dir=afl --cc=gcc --cc-bin=afl-g++

# Just need the static lib, not CLI or tests
make -f llvm/Makefile llvm/libbotan-1.11.a -j2
make -f afl/Makefile afl/libbotan-1.11.a -j2
