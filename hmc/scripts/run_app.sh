#
# A script for creating bridge and hyrbid mesh core
#
# NOTE: DON'T change the order of commands
#
#!/bin/sh

cd hmc/app/test
./clean.sh
./build.sh
cd ../../..
cp hmc/app/test/a.out .
cp hmc/app/test/peer_info.txt

./a.out ctrl br0 1001
