#!/bin/sh
JETSON_NANO_KERNEL_SOURCE=/home/parallels/Workplace/nvidia/kernel_out/build
TOOLCHAIN_PREFIX=/home/parallels/Workplace/nvidia/gcc-linaro-7.3.1-2018.05-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu-

if [ "$1" = "1" ]
then
	make KLIB_BUILD=$JETSON_NANO_KERNEL_SOURCE ARCH=arm64 CROSS_COMPILE=${TOOLCHAIN_PREFIX} mrproper
else
	make KLIB_BUILD=$JETSON_NANO_KERNEL_SOURCE ARCH=arm64 CROSS_COMPILE=${TOOLCHAIN_PREFIX} defconfig-ath10k
	make KLIB_BUILD=$JETSON_NANO_KERNEL_SOURCE ARCH=arm64 CROSS_COMPILE=${TOOLCHAIN_PREFIX} -j8
	rm hmc/*.ko
	rm hmc.tgz
	find . -name '*.ko' -exec cp "{}" hmc \;
	tar -zcvf hmc.tgz hmc 
fi
