#
# A script for creating bridge and hyrbid mesh core
#
# NOTE: DON'T change the order of commands
#
#!/bin/sh

OUT=$(pwd)/hmc/module
BR_IP=192.168.90.10
MESH_ID=mymesh

if [ "$(id -u)" -ne 0 ]; then echo "run as root" >&2; exit 1; fi

if [ -d $OUT ]; then
	echo "=== Found $OUT ==="
else
	echo "=== Not found $OUT ==="
	exit
fi

echo "Remove hmc module"
rmmod hmc

echo "Remove mac60211 module"
rmmod mac60211

echo "Unattach br0 with eth0"
brctl delif br0 eth0
echo "Unattach br0 with mesh0"
brctl delif br0 mesh0
echo "Delete br0"
ifconfig br0 down
brctl delbr br0

echo "Reassign eth0's ip addr: ($BR_IP)"
ifconfig eth0 $BR_IP

rmmod bridge
echo "Remove bridge module"

echo "Reload wifi modules"
echo "Remove ath10k driver module"
rmmod ath10k_pci
rmmod ath10k_core
rmmod ath
echo "Remove mac80211 module"
rmmod mac80211
echo "Remove cfg80211 module"
rmmod cfg80211
echo "Remove compat module"
rmmod compat

sleep 1

echo "Insert compat module"
insmod $OUT/compat.ko
echo "Insert cfg80211 module"
insmod $OUT/cfg80211.ko
echo "Insert mac80211 module"
insmod $OUT/mac80211.ko
echo "Insert ath10k driver module"
insmod $OUT/ath.ko
insmod $OUT/ath10k_core.ko
insmod $OUT/ath10k_pci.ko
