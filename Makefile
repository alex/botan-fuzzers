

BOTAN_DIR=botan-master
CLANG_COV_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=undefined -fsanitize-coverage=edge,indirect-calls,8bit-counters
LLVM_FLAGS=-O2 -std=c++11 -pthread -I$(BOTAN_DIR)/llvm/build/include $(BOTAN_DIR)/llvm/libbotan-1.11.a -DUSE_LLVM_FUZZER libFuzzer.a $(CLANG_COV_FLAGS)

AFL_FLAGS=-O2 -std=c++11 -pthread -I$(BOTAN_DIR)/afl/build/include $(BOTAN_DIR)/afl/libbotan-1.11.a

SOURCES=entry.cpp fuzzer_points.h

PROGS=llvm_fuzz_tlsc llvm_fuzz_tls llvm_fuzz_cert llvm_fuzz_crl afl_fuzz_tlsc afl_fuzz_tls afl_fuzz_cert afl_fuzz_crl

all: $(PROGS)

llvm_fuzz_tlsc: $(SOURCES) libFuzzer.a
	clang++ entry.cpp -DFUZZER_POINT=fuzz_tls_client $(LLVM_FLAGS) -o $@

afl_fuzz_tlsc: $(SOURCES)
	afl-g++ entry.cpp -DFUZZER_POINT=fuzz_tls_client $(AFL_FLAGS) -o $@

llvm_fuzz_tls: $(SOURCES) libFuzzer.a
	clang++ entry.cpp -DFUZZER_POINT=fuzz_tls_server $(LLVM_FLAGS) -o $@

afl_fuzz_tls: $(SOURCES)
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
