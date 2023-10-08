cd userprog
make clean
make
cd build
source ../../activate
pintos-mkdisk filesys.dsk 10
pintos --fs-disk filesys.dsk -p tests/filesys/base/syn-read:syn-read -p tests/filesys/base/child-syn-read:child-syn-read -- -q  -f run syn-read 
pintos --fs-disk filesys.dsk -p tests/userprog/no-vm/multi-oom:multi-oom -- -q  -f run multi-oom