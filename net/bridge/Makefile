#
# Makefile for the IEEE 802.1d ethernet bridging layer.
#

obj-$(CPTCFG_BRIDGE) += bridge.o

bridge-y	:= br.o br_device.o br_fdb.o br_forward.o br_if.o br_input.o br_hmc.o \
			br_ioctl.o br_stp.o br_stp_bpdu.o \
			br_stp_if.o br_stp_timer.o br_netlink.o

bridge-$(CPTCFG_SYSFS) += br_sysfs_if.o br_sysfs_br.o

bridge-$(subst m,y,$(CPTCFG_BRIDGE_NETFILTER)) += br_nf_core.o

#br_netfilter-y := br_netfilter_hooks.o
#br_netfilter-$(subst m,y,$(CONFIG_IPV6)) += br_netfilter_ipv6.o
#obj-$(CONFIG_BRIDGE_NETFILTER) += br_netfilter.o

bridge-$(CPTCFG_BRIDGE_IGMP_SNOOPING) += br_multicast.o br_mdb.o

bridge-$(CPTCFG_BRIDGE_VLAN_FILTERING) += br_vlan.o

#bridge-$(CONFIG_NET_SWITCHDEV) += br_switchdev.o

#obj-$(CONFIG_NETFILTER) += netfilter/
