#!/bin/bash

# 定义VPN文件夹路径
VPN_FOLDER="test_data"

# 遍历VPN文件夹中的所有pcap文件
for pcap_file in "$VPN_FOLDER"/*.pcap
do
  # 对每个pcap文件执行zeek命令
  echo "Processing $pcap_file..."
  zeek -C -r "$pcap_file" op_fp.zeek
done

echo "All pcap files have been processed."

