#!/bin/sh
# ============================================================
# B3: 启用 HNAT 硬件加速 (MT7621 PPE)
# 复刻原厂 GL 固件的 flow_offloading_hw 配置
# ============================================================
# 原厂 firewall defaults:
#   flow_offloading=1
#   flow_offloading_hw=1
# 25.12 firewall4 支持这两个选项, 启用后:
#   - 软件 flow offload (nf_flow_table)
#   - 硬件 flow offload (mtk_ppe, NET_MEDIATEK_SOC)
uci -q set firewall.@defaults[0].flow_offloading='1'
uci -q set firewall.@defaults[0].flow_offloading_hw='1'
uci -q commit firewall

# 确保 PPE 驱动加载(内建内核, 但确保 mtk_ppe debugfs 可用)
# mtk_ppe 由 NET_MEDIATEK_SOC 内建, 无需 modprobe

# 加载 flowtable 内核模块(若尚未加载)
[ -f /sys/module/nf_flow_table/parameters ] || modprobe nf_flow_table 2>/dev/null
[ -f /sys/module/nf_flow_table_hw/parameters ] || modprobe nf_flow_table_hw 2>/dev/null
[ -f /sys/module/nft_flow_offload/parameters ] || modprobe nft_flow_offload 2>/dev/null

exit 0
