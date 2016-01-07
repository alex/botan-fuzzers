

BOTAN_DIR=botan
CLANG_COV_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=undefined -fsanitize-coverage=edge,indirect-calls,8bit-counters
LLVM_FLAGS=-O2 -std=c++11 -pthread -I$(BOTAN_DIR)/llvm/build/include $(BOTAN_DIR)/llvm/libbotan-1.11.a -DUSE_LLVM_FUZZER libFuzzer.a $(CLANG_COV_FLAGS)

AFL_FLAGS=-O2 -std=c++11 -pthread -I$(BOTAN_DIR)/afl/build/include $(BOTAN_DIR)/afl/libbotan-1.11.a

SOURCES=entry.cpp fuzzer_points.h

FUZZERS=fuzz_p256 fuzz_bn_square fuzz_tls_client fuzz_tls_server fuzz_cert fuzz_crl

PROGS=llvm_fuzz_tls_client llvm_fuzz_tls_server llvm_fuzz_cert llvm_fuzz_crl llvm_fuzz_p256 llvm_fuzz_p384 llvm_fuzz_sqr llvm_ecc_points \
      afl_fuzz_tls_client afl_fuzz_tls_server afl_fuzz_cert afl_fuzz_crl afl_fuzz_p256 afl_fuzz_p384 afl_fuzz_sqr afl_ecc_points

all: $(PROGS)

llvm_fuzz_p256: $(SOURCES) libFuzzer.a
	clang++ entry.cpp -DFUZZER_POINT=fuzz_p256 $(LLVM_FLAGS) -o $@

afl_fuzz_p256: $(SOURCES) libFuzzer.a
	afl-g++ entry.cpp -DFUZZER_POINT=fuzz_p256 $(AFL_FLAGS) -o $@

llvm_fuzz_p384: $(SOURCES) libFuzzer.a
	clang++ entry.cpp -DFUZZER_POINT=fuzz_p384 $(LLVM_FLAGS) -o $@

afl_fuzz_p384: $(SOURCES) libFuzzer.a
	afl-g++ entry.cpp -DFUZZER_POINT=fuzz_p384 $(AFL_FLAGS) -o $@

llvm_fuzz_ecc_points: $(SOURCES) libFuzzer.a
	clang++ entry.cpp -DFUZZER_POINT=fuzz_ecc_points $(LLVM_FLAGS) -o $@

afl_fuzz_ecc_points: $(SOURCES) libFuzzer.a
	afl-g++ entry.cpp -DFUZZER_POINT=fuzz_ecc_points $(AFL_FLAGS) -o $@

llvm_fuzz_sqr: $(SOURCES) libFuzzer.a
	clang++ entry.cpp -DFUZZER_POINT=fuzz_bn_square $(LLVM_FLAGS) -o $@

afl_fuzz_sqr: $(SOURCES) libFuzzer.a
	afl-g++ entry.cpp -DFUZZER_POINT=fuzz_bn_square $(AFL_FLAGS) -o $@

llvm_fuzz_tls_client: $(SOURCES) libFuzzer.a
	clang++ entry.cpp -DFUZZER_POINT=fuzz_tls_client $(LLVM_FLAGS) -o $@

afl_fuzz_tls_client: $(SOURCES)
	afl-g++ entry.cpp -DFUZZER_POINT=fuzz_tls_client $(AFL_FLAGS) -o $@

llvm_fuzz_tls_server: $(SOURCES) libFuzzer.a
	clang++ entry.cpp -DFUZZER_POINT=fuzz_tls_server $(LLVM_FLAGS) -o $@

afl_fuzz_tls_server: $(SOURCES)
	afl-g++ entry.cpp -DFUZZER_POINT=fuzz_tls_server $(AFL_FLAGS) -o $@

llvm_fuzz_cert: $(SOURCES) libFuzzer.a
	clang++ entry.cpp -DFUZZER_POINT=fuzz_cert $(LLVM_FLAGS) -o $@

afl_fuzz_cert: $(SOURCES)
	afl-g++ entry.cpp -DFUZZER_POINT=fuzz_cert $(AFL_FLAGS) -o $@

llvm_fuzz_crl: $(SOURCES) libFuzzer.a
	clang++ entry.cpp -DFUZZER_POINT=fuzz_crl $(LLVM_FLAGS) -o $@

afl_fuzz_crl: $(SOURCES)
	afl-g++ entry.cpp -DFUZZER_POINT=fuzz_crl $(AFL_FLAGS) -o $@

clean:
	rm -f $(PROGS)

libFuzzer.a: libFuzzer
	cd libFuzzer && clang -c -g -O2 -std=c++11 *.cpp
	ar cr libFuzzer.a libFuzzer/*.o

setup:
	svn co https://github.com/llvm-mirror/llvm/trunk/lib/Fuzzer libFuzzer
	./setup-botan.sh

update:
	cd botan && git pull
	svn co https://github.com/llvm-mirror/llvm/trunk/lib/Fuzzer libFuzzer
