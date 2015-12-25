
This is a quick and dirty framework for fuzzing various entry points into the
botan crypto library (https://github.com/randombit/botan), currently with LLVM's
libFuzzer and AFL.

This is contained as a separate project from Botan itself for a number of reasons:

- It requires tools which are not always available out of the box, and is not
  really intended to be used by an end-user (vs an evaluator/auditor).

- Fuzzing the library requires building a library with certain critical checks
  (like signature validity) disabled. That's what the neuter_crypto.patch is
  for. As the resulting binary is effectively silently broken, it's important to
  make sure there is no chance this would happen to a production binary (thus
  for example adding a configure.py flag --disable-security-checks is out).

- This repo also contains corpus files for the various input types, as
  discovered by libFuzer and/or AFL. By saving the corpus data to git
  we can pre-seed future runs of the fuzzers which lets the fuzzers be
  more effective over time. These files are small individually but
  quite large in aggregate, and there is no reason to include them
  alongside the library itself.

entry.cpp is the entry point for the fuzzer (either LLVM or AFL,
depending on the flags set on the command line)

To add a new fuzzer point, add a suitable function to fuzzer_points.h,
with this signature:

int fuzzer_point(const uint8_t buf[], size_t len);

then add it to the Makefile.

The LLVM fuzzer binaries can be run directly, but need a few command line
args to tweak behavior:

  $ ./llvm_fuzz_cert corpus/cert  -max_len=512 -timeout=10 -report_slow_units=1

For TLS try -max_len=4000

AFL has fewer knobs, and the few that exist seem to self-tune fine:

  $ afl-fuzz -i corpus/cert -o afl_cert_output ./afl_fuzz_cert

TODO:

Support for KLEE (https://klee.github.io)

Scripts to merge and afl-cmin corpus before saving

