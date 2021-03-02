#
# A script for creating bridge and hyrbid mesh core
#
# NOTE: DON'T change the order of commands
#
#!/bin/sh

OUT=hmc
BR_IP=192.168.90.10
MESH_ID=mymesh

#rm -rf hmc
#rm -rf hmc.tgz
#cp ~/hmc.tgz .
#tar -xvf hmc.tgz

echo "Remove hmc module"
sudo rmmod hmc

echo "Remove mac60211 module"
sudo rmmod mac60211

echo "Unattach br0 with eth0"
sudo brctl delif br0 eth0
echo "Unattach br0 with mesh0"
sudo brctl delif br0 mesh0
echo "Delete br0"
sudo ifconfig br0 down
sudo brctl delbr br0

echo "Reassign eth0's ip addr: ($BR_IP)"
sudo ifconfig eth0 $BR_IP

sudo rmmod bridge
echo "Remove bridge module"

echo "Reload wifi modules"
echo "Remove ath10k driver module"
sudo rmmod ath10k_pci
sudo rmmod ath10k_core
sudo rmmod ath
echo "Remove mac80211 module"
sudo rmmod mac80211
echo "Remove cfg80211 module"
sudo rmmod cfg80211
echo "Remove compat module"
sudo rmmod compat

sleep 1

echo "Insert compat module"
sudo insmod $OUT/compat.ko
echo "Insert cfg80211 module"
sudo insmod $OUT/cfg80211.ko
echo "Insert mac80211 module"
sudo insmod $OUT/mac80211.ko
echo "Insert ath10k driver module"
sudo insmod $OUT/ath.ko
sudo insmod $OUT/ath10k_core.ko
sudo insmod $OUT/ath10k_pci.ko
