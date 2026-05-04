# Как собрать Libxml2

Обёртка `fuzz_driver.c`
```c
#include "libxml/parser.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 2) return 0;

    FILE *f = fopen(argv[1], "rb");
    if (!f) return 0;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    if (size <= 0) { fclose(f); return 0; }
    fseek(f, 0, SEEK_SET);

    char *data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);

    xmlDocPtr doc = xmlReadMemory(data, size, "noname.xml", NULL, 0);
    if (doc) xmlFreeDoc(doc);

    free(data);
    return 0;
}
```

## Сборка без инструментации

```bash
git clone https://gitlab.gnome.org/GNOME/libxml2.git
cd libxml2/
./autogen.sh
CC=afl-cc CFLAGS="-O0 -g" ./configure --disable-shared --enable-static
make -j$(nproc)

afl-cc -O0 -g  fuzz_driver.c  ./.libs/libxml2.a  -lz -lm -ldl -lpthread  -I./include  -o fuzz_target_not_instrumented

afl-fuzz -i ./in -o ./out -- ./fuzz_target_not_instrumented @@
```

## Сборка с инструментацией

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
while read src; do     echo "Compiling $src..."; clang -O0 -g -fno-discard-value-names -emit-llvm  -I./include -I. -D_REENTRANT -DHAVE_CONFIG_H -c "$src" -o "bitcode/$(basename "$src" .c).bc"; done < sources.txt

clang -O0 -g -fno-discard-value-names -emit-llvm -I./include -I. -D_REENTRANT -DHAVE_CONFIG_H  -c fuzz_driver.c -o bitcode/fuzz_driver.bc

llvm-link bitcode/*.bc -o libxml2_fuzz.bc

# проверка что только 1 main
llvm-nm libxml2_fuzz.bc | grep " T main"

# проверка содержимого файла, должно быть: LLVM IR bitcode
file libxml2_fuzz.bc

# команда, чтобы из .bc файла получить .ll
llvm-dis libxml2_fuzz.bc -o libxml2_fuzz.ll

# отметить уязвимое место если нужно
echo "[file: parser.c]
function: xmlReadMemory
line: 13473" > vulnerabilities.cfg

opt -load ../llvm/VulnPathPass.so -vuln-path libxml2_fuzz.ll -o instrumented.ll 2> pass_debug.log

afl-cc -O0 -g -fno-pie -no-pie instrumented.ll -lpthread -lz -lm -ldl -o fuzz_target

# запуск фаззинга
afl-fuzz -i ./in -o ./out -- ./fuzz_target @@
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

Список функций вызываемых по указателю:

* xmlInitParserInternal
* xmlPosixStrdup
* xmlMemRead
* xmlSAX2SetDocumentLocator
* endOfInput
* xmlSAX2StartDocument
* xmlSAX2StartElementNs
* xmlSAX2EndElementNs
* xmlSAX2EndDocument
* xmlMemClose
