#
# A script for creating bridge and hyrbid mesh core
#
# NOTE: DON'T change the order of commands
#
#!/bin/sh

DIR=/home/test/workplace/hmc
OUT=$DIR/hmc/module
BR_IP=192.168.90.10
MESH_ID=mymesh

HMC_TAR=hmc.tgz
FILE=`find . -name $HMC_TAR -print -quit`

#set -e

if [ "$(id -u)" -ne 0 ]; then echo "run as root" >&2; exit 1; fi

if [ -n "$FILE" ]; then
	echo "=== Found $HMC_TAR ==="
else
	echo "=== Not found $HMC_TAR ==="
	exit
fi

if [ -d $OUT ]; then
	echo "=== Found $OUT ==="
else
	echo "=== Not found $OUT ==="
	exit
fi

rm -rf $DIR/hmc
tar -xvf $DIR/hmc.tgz -C $DIR

rmmod hmc
echo "Remove hmc module"

rmmod mac60211
echo "Remove mac60211 module"

rmmod bridge
echo "Remove bridge module"

rmmod ath10k_pci
rmmod ath10k_core
rmmod ath
echo "Remove ath10k driver module"
rmmod mac80211
echo "Remove mac80211 module"
rmmod cfg80211
echo "Remove cfg80211 module"
rmmod compat
echo "Remove compat module"

sleep 1

insmod $OUT/compat.ko
echo "Insert compat module"
insmod $OUT/cfg80211.ko
echo "Insert cfg80211 module"
insmod $OUT/mac80211.ko
echo "Insert mac80211 module"
insmod $OUT/ath.ko
insmod $OUT/ath10k_core.ko
insmod $OUT/ath10k_pci.ko
echo "Insert ath10k driver module"

insmod $OUT/bridge.ko
echo "Insert bridge module"

sleep 1

echo "Add br0"
brctl addbr br0
echo "Bind eth0 with br0"
brctl addif br0 eth0
echo "Bring up br0"
ifconfig br0 up
echo "Clean up eth0's ip addr"
ifconfig eth0 0.0.0.0
echo "Assign ip addr ($BR_IP) for br0"
ifconfig br0 $BR_IP

echo "Assign mesh id for $MESH_ID"
iw dev wlan0 interface add mesh0 type mp mesh_id $MESH_ID
ifconfig wlan0 down
ifconfig mesh0 up
echo "Bind mesh0 with br0"
brctl addif br0 mesh0

brctl show

sleep 1

echo "Insert mac60211 module "
insmod $OUT/mac60211.ko

echo "Insert hmc module "
insmod $OUT/hmc.ko
