# Как собрать Libxml2

```bash
unset CC
unset CXX
unset CFLAGS
unset LLVM_COMPILER

git clone https://gitlab.gnome.org/GNOME/libxml2.git
cd libxml2/
./autogen.sh

CC=clang ./configure --disable-shared --enable-static
# export LLVM_COMPILER=clang
# make CC=wllvm CXX=wllvm++ -j$(nproc)

mkdir bitcode
while read src; do     echo "Compiling $src...";     clang -O0 -g -fno-discard-value-names -emit-llvm           -I./include -I.           -D_REENTRANT -DHAVE_CONFIG_H           -c "$src" -o "bitcode/$(basename "$src" .c).bc"; done < sources.txt

clang -O0 -g -fno-discard-value-names -emit-llvm       -I./include -I.       -D_REENTRANT -DHAVE_CONFIG_H       -c fuzz_driver.c -o bitcode/fuzz_driver.bc

llvm-link bitcode/*.bc -o libxml2_fuzz.bc

# проверка что только 1 main
llvm-nm libxml2_fuzz.bc | grep " T main"

# проверка содержимого файла, должно быть: LLVM IR bitcode
file libxml2_fuzz.bc

# команда, чтобы из .bc файла получить .ll
llvm-dis libxml2_fuzz.bc -o libxml2_fuzz.ll

opt -load ../llvm/VulnPathPass.so -vuln-path libxml2_fuzz.ll -o instrumented.ll 2> pass_debug.log

afl-cc -O0 -g -fno-pie -no-pie instrumented.ll -lpthread -lz -lm -ldl -o fuzz_target

afl-fuzz -i ../llvm/seeds/ -o out -- /fuzz-target

cp fuzz_target ../llvm/
```


sources.txt
```
buf.c
catalog.c
chvalid.c
debugXML.c
dict.c
encoding.c
entities.c
error.c
globals.c
hash.c
HTMLparser.c
HTMLtree.c
list.c
nanohttp.c
parser.c
parserInternals.c
pattern.c
relaxng.c
SAX2.c
schematron.c
threads.c
tree.c
uri.c
valid.c
xinclude.c
xlink.c
xmlIO.c
xmlmemory.c
xmlmodule.c
xmlreader.c
xmlregexp.c
xmlsave.c
xmlschemas.c
xmlschemastypes.c
xmlstring.c
xmlwriter.c
xpath.c
xpointer.c
```

```
rm -rf bitcode/
mkdir bitcode
```