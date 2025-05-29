#!/bin/bash

# 等待 relayer 的 9100 端口就绪
wait-for-it.sh relayer:9100 -t 60 -- echo "Relayer is ready"

# 启动服务
exec /app/bitvm2-node 