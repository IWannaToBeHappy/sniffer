# sniffer
源代码组织架构：
	Main.py:	GUI部分，负责显示软件页面。
	Sniffer.py:后台抓包并解析部分，负责调用winpcap对指定网卡进行抓包。
	Layers：包解析部分，以插件的形式添加数据解析支持，在实验中实现了ethernet、icmp、ipv4、ipv6、tcp、udp等协议的识别。如果要添加新的协议支持，只需要在layers文件夹中新建类，该类应该以Protocol为父类，Protocol是一个BigEndianStructure的一个自定义子类。新定义的协议类需要至少填写以下字段：
	_fields_字段，表示协议的数据格式；如果协议还能支持下层协议，
	entertypes字段：表示协议能够识别的上层协议；
	self.info，表示协议在详细信息页显示出的信息，
	self.header_len，表示协议头的长度

_fields_中以协议格式顺序将数据分割为各个字段，self.header_len从字段中直接读取，最后构造self.info，在详细信息中显示数据包的源端口和目的端口。因为udp无下层协议字段，没有entertypes字段。
在实现新类后，将类以及其对应的字段添加到__init__.py的str2protoClass中，保证key值与类相匹配，软件即可自动识别新协议。（Key值应与entertypes字段内容一致）
