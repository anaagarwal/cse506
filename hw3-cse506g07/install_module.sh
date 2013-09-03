umount /mnt
rmmod wrapfs
cd /usr/src/hw3-cse506g07
make
make modules
make modules_install install

insmod /usr/src/hw3-cse506g07/fs/wrapfs/wrapfs.ko
mount -t wrapfs  /n/scratch  /mnt -o mmap


