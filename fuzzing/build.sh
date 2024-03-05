cd "$SRC"/pdfminer.six
pip3 install .[dev]

# Build fuzzers in $OUT
for fuzzer in $(find dev/fuzzing -name 'fuzz_*.py');do
  compile_python_fuzzer "$fuzzer"
done
zip -q $OUT/pdfminer_fuzzer_seed_corpus.zip $SRC/corpus/*
