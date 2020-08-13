# backport-ak6e
This is an experimental wireless driver for ak6e. If you'd like to play around, please do the following to compile:

```
$ make defconfig-ak6e
$ make -j8
```

You will see its module named as `ak6e.ko` under `drivers/net/wireless/akiranet/`.

To be clean:

```
$ make mrproper
```

If you want to test out a real one, you can compile ath10k driver:

```
$ make defconfig-ath10k
$ make -j8
```
You will see its modules under `driver/net/wireless/ath/ath10k/`.

More information about backport please visit the page:

https://backports.wiki.kernel.org/index.php/Main_Page

