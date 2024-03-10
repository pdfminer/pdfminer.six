cd "$SRC"/pdfminer.six
pip3 install .[dev]

# Build fuzzers in $OUT
for fuzzer in $(find fuzzing -name '*_fuzzer.py');do
  compile_python_fuzzer "$fuzzer"
  base_name=$(basename "$fuzzer")
  base_name_no_ext=${base_name%.*}
  zip -q $OUT/"$base_name_no_ext".zip $SRC/corpus/*
done
