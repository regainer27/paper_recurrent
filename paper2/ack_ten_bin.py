import pyshark
from scapy.all import *
import matplotlib.pyplot as plt
import numpy as np
# import pandas as pd
import csv
import gc
from selenium.webdriver.common.devtools.v85.io import close

ACK_packet_region=[122,144]
def ACK_ten_bin(Flow_set):
    # 需要处理数据包
    global  ACK_packet_region
    Flow_length=len(Flow_set)
    bin_length=int(Flow_length/10)
    ACK_bin=[] #记录ACK分布的百分比
    ack_sum=0
    for i in range(0,9):
        ack_num=0
        for j in range(i*bin_length,(i+1)*bin_length):
            cur_packet=Flow_set[j]
            if cur_packet['tcp'].flags == "0x0010":
            # if cur_len > ACK_packet_region[0] and cur_len < ACK_packet_region[1]:
                ack_num+=1
                ack_sum +=1
        ACK_bin.append(ack_num)
    temp=[]
    if ack_sum==0:
        return ACK_bin
    for i in ACK_bin:
        temp.append(round((i/ack_sum),3))
    ACK_bin=temp
    return ACK_bin

def ACK_ten_bin_openvpn(Flow_set):
    global  ACK_packet_region
    Flow_length=len(Flow_set)
    bin_length=int(Flow_length/10)
    ACK_bin=[] #记录ACK分布的百分比
    ack_sum=0
    for i in range(0,9):
        ack_num=0
        for j in range(i*bin_length,(i+1)*bin_length):
            cur_len=Flow_set[j]
            if cur_len > ACK_packet_region[0] and cur_len < ACK_packet_region[1]:
                ack_num+=1
                ack_sum +=1
        ACK_bin.append(ack_num)
    temp=[]
    if ack_sum==0:
        return ACK_bin
    for i in ACK_bin:
        temp.append(round((i/ack_sum),3))
    ACK_bin=temp
    return ACK_bin


def get_openvpn_stream(capture):
    stream_set=[]
    flow_set = []
    start_append = 0
    # 由于使用用的openvpnserver与论文中差异较大，其中最显著的差别在于ack包不再是定长，因此改用一定的范围来判别ack包
    for packet in capture:
        if 'ip' in packet:
            try:
                packet_len=len(packet)
            #     分析openvpn流量，因为数据集比较小，而且目前仅有一台openvpn server 设备，获得多条也没有意义。
                if packet_len==439 :
                    start_append=1
            #     因为自己采集的openvpn的流量中，每条流的第一个数据包的长度为439，所以以此作为判别依据。
                    if len(flow_set)>50:
                        stream_set.append(flow_set)
                        flow_set=[]
                    else:
                        flow_set=[]
                if start_append:
                    flow_set.append(packet_len)
            except:
                print("error")
                continue
    ack_bin_set=[]
    for i in stream_set:
        ack_bin=ACK_ten_bin_openvpn(i)
        print(ack_bin)
        ack_bin_set.append(ack_bin)
    x=range(0,9)
    plt.ylim(0, 1)
    for i in ack_bin_set:
        plt.plot(x,i)
    plt.show()
def filiter_stream(capture,start,end):
    i = 0
    sessions = defaultdict(list)
    # 按照流进行划分
    for i in range(start,end):
        packet = capture.next()
        if 'ip' in packet:
            try:
                packet_time = float(packet.sniff_timestamp)
                session_key = (
                    packet['ip'].src, packet['ip'].dst, packet['tcp'].srcport, packet['tcp'].dstport,
                    packet['ip'].proto)
                session_key_2 = (
                    packet['ip'].dst, packet['ip'].src, packet['tcp'].dstport, packet['tcp'].srcport,
                    packet['ip'].proto)
                # if session_key in satifier_list or session_key_2 in satifier_list:
                #     continue
                if session_key in sessions.keys() or session_key_2 in sessions.keys():
                    if not session_key in sessions.keys():
                        session_key = session_key_2
                    if len(sessions[session_key]) == 1:
                        if packet['tcp'].flags == "0x0012":
                            sessions[session_key].append(packet)
                        else:
                            sessions.pop(session_key, None)
                    # `
                    else:
                        sessions[session_key].append(packet)
                else:
                    if packet['tcp'].flags == "0x0002":
                        sessions[session_key].append(packet)
            except:
                print("error")
                continue
    # 对不同协议进行划分
    ack_bin_set=[]
    for key,value in sessions.items():
        if len(value)<50:
            continue
        ack_bin=ACK_ten_bin(value)
        print(ack_bin)
        ack_bin_set.append(ack_bin)
    x=range(0,9)
    plt.ylim(0, 1)
    for i in ack_bin_set:
        plt.plot(x,i)
    plt.show()


if __name__=="__main__":
    # tcp_traffic=rdpcap("tcp.pcap")
    capture = pyshark.FileCapture("openvpn only2.pcapng", keep_packets=False)
    get_openvpn_stream(capture)
        # 其中ack相关的数据确实在前5bin出现概率高点。
    capture = pyshark.FileCapture("tcp.pcap", keep_packets=False)
    filiter_stream(capture,1,10000)
