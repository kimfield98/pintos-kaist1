cd vm
make clean
make
cd build
source ../../activate
pintos-mkdisk filesys.dsk 10
# pintos --fs-disk filesys.dsk -- -q  -threads-tests -f run alarm-single
# pintos --gdb --fs-disk filesys.dsk -- -q  -threads-tests -f run alarm-single
# pintos --fs-disk filesys.dsk -p tests/userprog/close-normal:close-normal -p ../../tests/userprog/sample.txt:sample.txt -- -q -f run close-normal
# pintos --fs-disk filesys.dsk -p tests/userprog/read-normal:read-normal -p ../../tests/userprog/sample.txt:sample.txt -- -f run read-normal
# pintos --gdb --fs-disk filesys.dsk -p tests/userprog/fork-once:fork-once -- -q  -f run fork-once 
pintos --gdb --fs-disk filesys.dsk -p tests/userprog/fork-once:fork-once -- -q  -f run fork-once 