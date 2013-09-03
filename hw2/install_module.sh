umount /tmp
rmmod wrapfs
cd /usr/src/hw2-anaagarwal
make
make modules
make modules_install install

insmod /usr/src/hw2-anaagarwal/fs/wrapfs/wrapfs.ko
mount -t wrapfs  /n/scratch/  /tmp -o user_xattr


