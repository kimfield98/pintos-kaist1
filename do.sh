cd userprog
make clean
make
cd build
source ../../activate
pintos-mkdisk filesys.dsk 10
pintos --fs-disk filesys.dsk -p tests/userprog/args-many:args-many -- -q -f run 'args-many a b c d e f g h i j k l m n o p q r s t u v'
# pintos --fs-disk filesys.dsk -p tests/userprog/args-single:args-single --gdb -- -f run 'args-single onearg'