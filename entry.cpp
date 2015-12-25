
#include "fuzzer_points.h"

#if !defined(FUZZER_POINT)
  #error "FUZZER_POINT must be set as macro on build line"
#endif

#if defined(USE_LLVM_FUZZER)

// Called by main() in libFuzzer
extern "C" int LLVMFuzzerTestOneInput(const uint8_t in[], size_t len)
   {
   return FUZZER_POINT(in, len);
   }

#else

// Read stdin for AFL

#include <stdio.h>

int main(int argc, char* argv[])
   {
   std::vector<uint8_t> buf(4096); // max read
   size_t got = ::fread(buf.data(), 1, buf.size(), stdin);
   buf.resize(got);
   return FUZZER_POINT(buf.data(), got);
   }

#endif
