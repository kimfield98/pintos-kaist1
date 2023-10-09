cd userprog
make clean
make
cd build
source ../../activate
pintos-mkdisk filesys.dsk 10
# pintos -v -k -T 600 -m 20 -m 20   --fs-disk=10 -p tests/userprog/no-vm/multi-oom:multi-oom -- -q   -f run multi-oom
# pintos --fs-disk filesys.dsk -p tests/filesys/base/syn-read:syn-read -p tests/filesys/base/child-syn-read:child-syn-read -- -q  -f run syn-read 
# pintos --fs-disk filesys.dsk -p tests/userprog/no-vm/multi-oom:multi-oom -- -q  -f run multi-oom
# pintos --gdb --fs-disk filesys.dsk -p tests/userprog/no-vm/multi-oom:multi-oom -- -q  -f run multi-oom