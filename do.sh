cd userprog
make clean
make
cd build
source ../../activate
pintos-mkdisk filesys.dsk 10
pintos --fs-disk filesys.dsk -p tests/userprog/fork-once:fork-once -- -q  -f run fork-once 
pintos --fs-disk filesys.dsk -p tests/userprog/fork-multiple:fork-multiple -- -q  -f run fork-multiple 
pintos --fs-disk filesys.dsk -p tests/userprog/fork-recursive:fork-recursive -- -q  -f run fork-recursive 
pintos --fs-disk filesys.dsk -p tests/userprog/fork-read:fork-read -p ../../tests/userprog/sample.txt:sample.txt -- -q  -f run fork-read 
pintos --fs-disk filesys.dsk -p tests/userprog/fork-close:fork-close -p ../../tests/userprog/sample.txt:sample.txt -- -q  -f run fork-close -p tests/userprog/fork-boundary:fork-boundary -- -q  -f run fork-boundary 