"""
作业第三天

pcap 文件格式学习
自己对pcap文件格式的理解，并在十六进制编辑器中打开下面的数据包文件，截图框选出文件头和相关字段的位置和范围

文件：链接: https://pan.baidu.com/s/1B9dkgVnw2Ua37vbN7MiOIg 提取码: cuwl

对 Pcap 的理解
Pcap，Packet Capture，操作系统提供给应用程序用于捕获网络流量的接口，应用程序通过这个接口可以获取到网络流量数据，Pacp 捕获的是链路层的数据
Pcap 格式：Pcap 头，packet1 头，packet1 数据，packet 2 头，packet2 数据，。。。
Pcap 头： 24 字节
    ● 4，Pcap 开始标记，同时标记大端模式（0xa1b2c3d4）还是小端模式（0xd4c3b2a1）
      ○ 如果是小端模式，后面的每个定义好的数据块都要倒着读取
    ● 2+2，大版本号 + 小版本号
    ● 4，标准时间类型
    ● 4，时间戳精度
    ● 4，想要捕获的数据包大小
    ● 4，链路类型
packet header：16 字节
    ● 4，时间秒
    ● 4，时间微秒
    ● 4，数据帧长度
    ● 4，数据帧长度

文件内容理解如下
https://cdn.nlark.com/yuque/0/2022/png/973189/1652606543913-0207aeda-c9ac-4762-94de-046cc0c79512.png?x-oss-process=image%2Fresize%2Cw_1500%2Climit_0
"""