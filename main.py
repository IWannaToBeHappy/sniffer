
from ctypes import alignment
from tabnanny import verbose
import PyQt5
import sys
from sniffer import *
from PyQt5.QtWidgets import *
from json import loads
from PyQt5 import QtCore
from re import findall
from binascii import unhexlify

class MainWindow(QMainWindow):
    sin = pyqtSignal()

    def __init__(self) -> None:
        super().__init__()
        self.sniffer = Sniffer()
        self.sniffer.sin.connect(self.updateText)
        self.sin.connect(self.sniffer.stop_sniffer)
        self.pkt_buf = []
        self.show_buf = []
        self.initUI()
    
    def initUI(self):
        QtCore.QMetaObject.connectSlotsByName(self)
        self.statusBar().showMessage('来添加更多协议吧')# 状态栏

        # 列出所有网卡选项，用户选择其中一个网卡进行sniff，提示用户若仅支持Ethernet类型网卡
        self.get_network_interface()
        interface_select_label = QLabel("请选择网卡",self)
        interface_select = QComboBox(self)
        for name in self.network_interfaces.values():
            interface_select.addItem(name)
        interface_select.adjustSize()
        interface_select.move(50,50)
        interface_select_label.move(50,20)
        interface_select.activated[str].connect(self.changeInterface)
        
        # 点击开始按钮开始捕包，再次点击按钮停止捕包
        self.sniff_control = QPushButton('开始',self)
        self.sniff_control.setCheckable(True)
        self.sniff_control.move(600,40)
        self.sniff_control.clicked[bool].connect(self.sniff)
         
        # 显示列表显示所选包（若无过滤规则显示所有包），显示内容为时间、源IP、目的IP、最顶层协议
        self.text = QPlainTextEdit(self)
        self.text.setPlainText('%s %10s  %30s  %30s  %15s'%('序号','时间','源地址','目的地址','最高层协议'))
        self.text.setReadOnly(True)
        self.text.move(50,130)
        self.text.resize(1000,400)

        # 过滤器初始为零，用户输入过滤规则后，后台应用过滤规则
        self.filter = QLineEdit(self)
        self.filter.move(50,80)
        self.filter.resize(800,30)
        self.filter.returnPressed.connect(self.use_filter)

        # 点击help按钮弹出子窗口，窗口中为支持的过滤规则
        self.help = QPushButton('帮助',self)
        self.help.move(950,75)
        self.help.resize(50,40)
        self.help.clicked[bool].connect(self.show_help)

        # 点击窗口后弹出子窗口，窗口中显示所有筛选包的原始数据、详细解析信息
        self.raw_data = QPushButton('raw data',self)
        self.raw_data.move(860,75)
        self.raw_data.resize(80,40)
        self.raw_data.clicked[bool].connect(self.show_raw)
        
        self.setGeometry(300,300,1100,600)
        self.setWindowTitle('sniff')
        self.show()

        

    def get_network_interface(self):
        self.network_interfaces =  WinPcapDevices.list_devices()#{device_name:description}
    
    def changeInterface(self,text):
        self.interface = list(self.network_interfaces.keys())[list(self.network_interfaces.values()).index(text)]

    def sniff(self,pressed):
        if not hasattr(self,'interface'):
            QMessageBox.information(self,"错误","请选择支持Ethernet的网卡")
            self.sniff_control.setChecked(False)
            return
        if pressed:
            self.pkt_buf = []
            self.text.clear()
            self.text.setPlainText('%s %10s  %30s  %30s  %15s'%('序号','时间','源地址','目的地址','最高层协议'))
            self.sniff_control.setText('结束')
            self.sniff_control.setChecked(True)
            self.statusBar().showMessage('注意，选择非Ethernet网卡会造成非预期解析')
            QApplication.processEvents()
            self.sniffer.run(self.interface)
        else:
            self.sniff_control.setText('开始')
            self.sniff_control.setChecked(False)
            self.sin.emit()
            QApplication.processEvents()
    
    def updateText(self,dic):
        text = loads(dic)
        id = len(self.pkt_buf)
        text['id'] = id
        self.pkt_buf.append(text)
        time = datetime.datetime.fromtimestamp(text['time'],)
        protocol_list = text["protocol_list"]
        pkt_info = text["pkt_info"]
        pkt_data = text["pkt_data"]
        src,dst = 'Unknown','Unknown'
        for info in pkt_info:
            if 'dst' in info:
                dst = info['dst']
            if 'src' in info:
                src = info['src']
        info = '%3d |%20s | %30s | %30s | %s'%(id,str(time),src,dst,protocol_list[-1])
        self.text.appendPlainText(info)

    def use_filter(self):
        if self.pkt_buf == []:
            QMessageBox.information(self,"提示","是不是忘了抓包了→.→")
            return

        filter_text = self.filter.text()
        if len(filter_text) >= 100:
            QMessageBox.warning(self,"短点，你隔这搞注入呢")
        if filter_text == '':
            self.show_buf = self.pkt_buf
        else:
            self.show_buf = []
            for pkt in self.pkt_buf:
                try:
                    result = eval(filter_text)
                except:
                    continue
                if type(result)!=bool:
                    QMessageBox.information(self,"过滤规则应返回BOOL值")
                    return
                if result:
                    self.show_buf.append(pkt)

        self.text.clear()
        self.text.appendPlainText('%s %10s  %30s  %30s  %15s'%('序号','时间','源地址','目的地址','最高层协议'))   
        for pkt in self.show_buf:
            time = datetime.datetime.fromtimestamp(pkt['time'],)
            protocol_list = pkt["protocol_list"]
            pkt_info = pkt["pkt_info"]
            src,dst = 'Unknown','Unknown'
            for info in pkt_info:
                if 'dst' in info:
                    dst = info['dst']
                if 'src' in info:
                    src = info['src']
            info = '%3d |%20s | %30s | %30s | %s'%(pkt['id'],str(time),src,dst,protocol_list[-1])
            self.text.appendPlainText(info)

    def show_help(self):
        text = "程序维护以以下格式维护着数据包列表，输入规则将在每一个pkt上应用，当返回值为True时pkt将被展示."
        pattern = ("pkt = {\r\n"+
            "   'id':(int)pkt_id,\r\n"+
            "   'time':time,\r\n"+
            "   'protocol_list':list('protocol_name'),\r\n"+
            "   'pkt_info':[{'info_name':'info_value'},]\r\n"+
            "   'pkt_data':raw data\r\n}")
        text1 = "具体的pkt_info内容可以查看各协议源代码的info属性\r\n"
        text1 += "以下为常用示例：\r\n"
        text1 += "pkt['pkt_info'][1]['dst']=='127.0.0.1' or pkt['pkt_info'][1]['src']=='127.0.0.1' #IP地址筛选\r\n"
        text1 += "pkt.id == 1 #ID筛选\r\n"
        dialog = QDialog(self)
        dialog.resize(500,500)
        dialog_text = QPlainTextEdit(dialog)
        dialog_text.setPlainText(text)
        dialog_text.appendPlainText(pattern)
        dialog_text.appendPlainText(text1)
        dialog_text.setReadOnly(True)
        dialog_text.resize(dialog.size())
        dialog.show()

    def show_raw(self):
        if self.show_buf == []:
            QMessageBox.information(self,"提示","请先过滤包，若要显示所有包，可在过滤器中直接回车")
            return
        dialog = QDialog(self)
        dialog.setWindowTitle('Raw Data')
        dialog.resize(1200,700)

        dialog_text = QPlainTextEdit(dialog)
        dialog_text.setReadOnly(True)
        for pkt in self.show_buf:
            time = datetime.datetime.fromtimestamp(pkt['time'],)
            protocol_list = pkt["protocol_list"]
            pkt_info = pkt["pkt_info"]
            raw_data = pkt['pkt_data']
            text1 = 'Packet ID:%3d Time: %20s\r\n'%(pkt['id'],str(time))
            text2 = '协议解析:%s\r\n'%(str(protocol_list))
            text3 = '各层信息:%s\r\n'%(str(pkt_info))
            text4 = '原始数据:\r\n'
            text4 += '-'*140
            dialog_text.appendPlainText(text1+text2+text3+text4)
            raw_list = findall('.{32}',raw_data)
            raw_list.append(raw_data[len(raw_data)//32*32:])
            for raw in raw_list:
                text = ''
                x_list = findall('.{2}',raw)
                for x in x_list:
                    text+='%3s'%x
                text += ' '*4
                for x in x_list:
                    try:
                        _text='%s'%str(unhexlify(x),encoding="utf-8")
                        text+=_text
                        text+=' ' * (7-len(repr(_text)))
                    except:
                        text+='%-4s'%('·')
                dialog_text.appendPlainText(repr(text))
            dialog_text.appendPlainText('-'*140)

        
        hbox = QHBoxLayout()
        hbox.addWidget(dialog_text)
        vbox = QVBoxLayout()
        vbox.addLayout(hbox)
        dialog.setLayout(vbox)
        
        dialog.show()









app = QApplication(sys.argv)
ex = MainWindow()
sys.exit(app.exec_())