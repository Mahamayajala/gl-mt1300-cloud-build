# Kernel module build (used by OpenWrt kbuild via M=$(PKG_BUILD_DIR))
# 
# ccflags: OpenWrt ramips kernels build with -Werror (CONFIG_WERROR / kernel
# KCFLAGS).  Be robust against unused-variable/parameter which are harmless
# but would otherwise abort the whole build on a kernel upgrade.
ccflags-y += -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-parameter

obj-m := gl-sdk4-hw-info.o gl-sdk4-tertf.o
