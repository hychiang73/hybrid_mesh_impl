# SPDX-License-Identifier: GPL-2.0
obj-$(CPTCFG_MAC60211) += mac60211.o


# mac60211 objects
mac60211-y := \
	main.o \
	nl60211.o

# mac60211 mesh objects
mac60211-$(CPTCFG_MAC60211_MESH) += \
	ak60211_mesh.o \
	ak60211_mhwmp_mplink.o \
	ak60211_mtbl.o

ccflags-y += -Wall
