# Hybrid Mesh Core and PLC Mesh experiments
We've implemented the hybrid mesh core (HMC) in the bridge code and the mac60211 (PLC mesh) in the Linux network stack based on the ath10k wireless driver and r8168 ethernet driver.

All of them are still in progress (It's ended).

# Before compiling
You must install the following components into your host before compiling the backport driver.

`sudo apt-get install bison flex build-essential`
