cd userprog
make clean
make
cd build
source ../../activate
pintos-mkdisk filesys.dsk 10
# pintos --fs-disk filesys.dsk -p tests/userprog/fork-once:fork-once -- -q  -f run fork-once
# pintos --fs-disk filesys.dsk -p tests/userprog/rox-simple:rox-simple -- -q  -f run rox-simple
# pintos --fs-disk filesys.dsk -p tests/userprog/fork-recursive:fork-recursive -- -q  -f run fork-recursive 
pintos --fs-disk filesys.dsk -p tests/userprog/exec-arg:exec-arg -p tests/userprog/child-args:child-args -- -q  -f run exec-arg
# pintos --fs-disk filesys.dsk -p tests/userprog/fork-close:fork-close -p ../../tests/userprog/sample.txt:sample.txt -- -q  -f run fork-close -p tests/userprog/fork-boundary:fork-boundary -- -q  -f run fork-boundary 