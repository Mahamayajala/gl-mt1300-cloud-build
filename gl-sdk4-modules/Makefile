# ============================================================
# GL.iNet SDK4 kernel modules (clean-room reimplementation)
#
# Builds gl-sdk4-hw-info.ko and gl-sdk4-tertf.ko from source
# using the OpenWrt kernel build system.  Because they are
# compiled against whatever kernel is in the build tree, they
# automatically work on any OpenWrt version (22.03.4 today,
# future 23.05/24.10/... ) -- no lock-in to the original
# 5.10.176 vermagic.
#
# Build modes (set via make variable GL_MODULES_BUILD):
#   source   (default) - compile from ./src (clean-room, upgradeable)
#   original           - use the prebuilt GL .ko from ./original
#                        (only works on the exact kernel they were
#                         built for: 5.10.176, locks kernel version)
#
# Usage: enable with
#   CONFIG_PACKAGE_kmod-gl-sdk4-hw-info=y
#   CONFIG_PACKAGE_kmod-gl-sdk4-tertf=y
#
# NOTE: MTD (get_mtd_device_nm/mtd_read) and the core netfilter hook
# API (nf_register_net_hook) are built into the ramips kernel, so no
# extra kmod dependency is required.
# ============================================================
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=gl-sdk4-modules
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0

include $(INCLUDE_DIR)/package.mk

define KernelPackage/gl-sdk4-hw-info
  SUBMENU:=GL.iNet
  TITLE:=GL.iNet hardware info (/proc/gl-hw-info)
  FILES:=$(PKG_BUILD_DIR)/gl-sdk4-hw-info.ko
  AUTOLOAD:=$(call AutoProbe,gl_sdk4_hw_info)
endef

define KernelPackage/gl-sdk4-hw-info/description
  GL.iNet hardware info module. Provides /proc/gl-hw-info with the
  device MAC, serial, DDNS, etc. (clean-room reimplementation).
endef

define KernelPackage/gl-sdk4-tertf
  SUBMENU:=GL.iNet
  TITLE:=GL.iNet tertf traffic accounting (/proc/oui-tertf)
  FILES:=$(PKG_BUILD_DIR)/gl-sdk4-tertf.ko
  AUTOLOAD:=$(call AutoProbe,gl_sdk4_tertf)
endef

define KernelPackage/gl-sdk4-tertf/description
  GL.iNet tertf module. Provides /proc/oui-tertf with per-client
  traffic accounting (clean-room reimplementation).
endef

ifeq ($(GL_MODULES_BUILD),original)
# ---- use prebuilt original .ko (locked to 5.10.176) ----
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./original/*.ko $(PKG_BUILD_DIR)/
endef
define Build/Compile
	@echo "Using original GL modules (no compile)"
endef
else
# ---- default: compile clean-room source ----
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef
define Build/Compile
	$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)" modules
endef
endif

$(eval $(call KernelPackage,gl-sdk4-hw-info))
$(eval $(call KernelPackage,gl-sdk4-tertf))
