#
# A script for creating bridge and hyrbid mesh core
#
# NOTE: DON'T change the order of commands
#
#!/bin/sh

OUT=$(pwd)/hmc/modules
HMC_TAR=hmc.tgz
FILE=`find . -name $HMC_TAR -print -quit`
BR_IP=192.168.90.10
MESH_ID=mymesh

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

rm -rf hmc
tar -xvf hmc.tgz

sudo rmmod hmc
echo "Remove hmc module"

sudo rmmod mac60211
echo "Remove mac60211 module"

sudo rmmod bridge
echo "Remove bridge module"

sudo rmmod ath10k_pci
sudo rmmod ath10k_core
sudo rmmod ath
echo "Remove ath10k driver module"
sudo rmmod mac80211
echo "Remove mac80211 module"
sudo rmmod cfg80211
echo "Remove cfg80211 module"
sudo rmmod compat
echo "Remove compat module"

sleep 1

sudo insmod $OUT/compat.ko
echo "Insert compat module"
sudo insmod $OUT/cfg80211.ko
echo "Insert cfg80211 module"
sudo insmod $OUT/mac80211.ko
echo "Insert mac80211 module"
sudo insmod $OUT/ath.ko
sudo insmod $OUT/ath10k_core.ko
sudo insmod $OUT/ath10k_pci.ko
echo "Insert ath10k driver module"

sudo insmod $OUT/bridge.ko
echo "Insert bridge module"

sleep 1

echo "Add br0"
sudo brctl addbr br0
echo "Bind eth0 with br0"
sudo brctl addif br0 eth0
echo "Bring up br0"
sudo ifconfig br0 up
echo "Clean up eth0's ip addr"
sudo ifconfig eth0 0.0.0.0
echo "Assign ip addr ($BR_IP) for br0"
sudo ifconfig br0 $BR_IP

echo "Assign mesh id for $MESH_ID"
sudo iw dev wlan0 interface add mesh0 type mp mesh_id $MESH_ID
sudo ifconfig wlan0 down
sudo ifconfig mesh0 up
echo "Bind mesh0 with br0"
sudo brctl addif br0 mesh0

sudo brctl show

sleep 1

echo "Insert mac60211 module "
sudo insmod $OUT/mac60211.ko

echo "Insert hmc module "
sudo insmod $OUT/hmc.ko
