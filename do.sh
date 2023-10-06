cd userprog
make clean
make
cd build
source ../../activate
pintos-mkdisk filesys.dsk 10
# pintos --fs-disk filesys.dsk -p tests/userprog/read-normal:read-normal -p ../../tests/userprog/sample.txt:sample.txt -- -q -f run read-normal
pintos --fs-disk filesys.dsk -p tests/userprog/read-normal:read-normal -p ../../tests/userprog/sample.txt:sample.txt --gdb -- -f run read-normal