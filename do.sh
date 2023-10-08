cd userprog
make clean
make
cd build
source ../../activate
pintos-mkdisk filesys.dsk 10
# pintos --fs-disk filesys.dsk -p tests/userprog/fork-once:fork-once -- -q  -f run fork-once
# pintos --fs-disk filesys.dsk -p tests/userprog/rox-simple:rox-simple -- -q  -f run rox-simple
# pintos --fs-disk filesys.dsk -p tests/userprog/fork-multiple:fork-multiple -- -q  -f run fork-multiple 
# pintos --fs-disk filesys.dsk -p tests/userprog/wait-twice:wait-twice -p tests/userprog/child-simple:child-simple -- -q  -f run wait-twice
# pintos --fs-disk filesys.dsk -p tests/userprog/fork-close:fork-close -p ../../tests/userprog/sample.txt:sample.txt -- -q  -f run fork-close -p tests/userprog/fork-boundary:fork-boundary -- -q  -f run fork-boundary 
pintos --fs-disk filesys.dsk -p tests/userprog/exec-once:exec-once -p tests/userprog/child-simple:child-simple -- -q  -f run exec-once