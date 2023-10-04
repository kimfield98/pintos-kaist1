cd userprog
make clean
make
cd build
source ../../activate
pintos-mkdisk filesys.dsk 10
# pintos --fs-disk filesys.dsk -p tests/userprog/args-single:args-single -- -q -f run 'args-single onearg'
pintos --fs-disk filesys.dsk -p tests/userprog/args-single:args-single --gdb -- -f run 'args-single onearg'