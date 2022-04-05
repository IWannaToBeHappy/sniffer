from typing import Any
import layers
import threading
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5 import QtWidgets
from winpcapy import *
import datetime
from json import dumps


class Sniffer(QThread):

    sin = pyqtSignal(str)  # 解析所得包数据

    def __init__(self):
        super(Sniffer, self).__init__()
        self.stop = False

    def run(self, interface):
        def packet_callback(win_pcap, param, header, pkt_data):
            # pkt_data即为包数据
            # 解析包中的所有协议栈信息,并返回解析列表
            time = header.contents.ts.tv_sec  # 包时间
            protocol_list = []
            pkt_info = []
            data_idx = 0
            protocol_class = layers.Ethernet
            while protocol_class is not None:
                pkt = protocol_class(pkt_data[data_idx:])
                protocol_list.append(pkt.__class__.__name__)
                pkt_info.append(pkt.info)
                if pkt.encapsulated_proto == None or pkt.encapsulated_proto not in layers.str2protoClass.keys():
                    protocol_class = None
                else:
                    # support protocol
                    protocol_class = layers.str2protoClass[pkt.encapsulated_proto]
                data_idx += pkt.header_len
            self.sin.emit(
                dumps(
                    {
                        "time": time,
                        "protocol_list": protocol_list,
                        "pkt_info": pkt_info,
                        "pkt_data": pkt_data.hex()
                    }
                )
            )
            if self.stop == True:
                capture.stop()
            QtWidgets.QApplication.processEvents()

        self.stop = False
        with WinPcap(interface) as capture:
            capture.run(callback=packet_callback)

    def stop_sniffer(self):
        self.stop = True
