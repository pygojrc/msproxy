#!/bin/sh
# 使用 tini 转发信号并回收孤儿进程；Python 管理 Nginx 和 Xray 生命周期。
exec python3 /opt/msproxy/msproxy.py "$@"
