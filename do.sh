cd userprog
make clean
make
cd build
source ../../activate
pintos-mkdisk filesys.dsk 10
# pintos --fs-disk filesys.dsk -p tests/userprog/open-twice:open-twice -- -q -f run 'open-twice sample.txt'
pintos --fs-disk filesys.dsk -p tests/userprog/open-twice:open-twice --gdb -- -f run 'open-twice sample.txt'