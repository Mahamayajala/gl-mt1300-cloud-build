#!/bin/bash
# ============================================================
# 给 OpenWrt 22.03 nginx 包加 --with-http_gzip_static_module
# 原厂 GL 固件的 nginx -V 含此模块 (gzip_static on 服务 .gz 静态文件)
# 标准 OpenWrt 22.03 nginx 包【没有】编译它 —— 必须补上, 否则:
#   原厂 nginx.conf 的 "gzip_static on" 会导致 nginx 启动失败
# 用法: patch-nginx-gzipstatic.sh <packages-feed-源码目录>
# ============================================================
set -e

PKGS_DIR="${1:?用法: $0 <packages-feed源码目录>}"
MAKEFILE="$PKGS_DIR/net/nginx/Makefile"

if [ ! -f "$MAKEFILE" ]; then
  echo "错误: 找不到 $MAKEFILE"
  exit 1
fi

if grep -q "with-http_gzip_static_module" "$MAKEFILE"; then
  echo "gzip_static 已存在, 跳过"
else
  # nginx-ssl 变体的 ADDITIONAL_MODULES 行 (无缩进, 精确匹配)
  sed -i \
    's|^ADDITIONAL_MODULES:= --with-http_ssl_module$|ADDITIONAL_MODULES:= --with-http_ssl_module --with-http_gzip_static_module|' \
    "$MAKEFILE"
fi

echo "=== 验证 (应看到 with-http_gzip_static_module) ==="
grep -n "with-http_gzip_static_module\|ADDITIONAL_MODULES:=" "$MAKEFILE" | head -5
