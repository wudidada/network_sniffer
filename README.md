# 网络嗅探器

![](https://raw.githubusercontent.com/wudidada/pic/main/20220407192228.png)

- github地址：https://github.com/wudidada/network_sniffer

图形界面基于PyQt，嗅探功能基于Scapy。

## 使用说明

### 安装

```
pip install -r requirements.txt
python main.py
```

### 使用

1. 选择需要嗅探的网络设备，下拉NIC菜单即可选取。
2. 点击start开始嗅探，再次点击结束。
3. 选中数据包后即可在下面看到该包的详细信息及完整二进制内容。

### 过滤功能

在第二列有多个输入框可以对数据包进行过滤。

| 标签  | 过滤内容 |
| ----- | -------- |
| PRO   | 协议     |
| SRC   | 源IP     |
| SPORT | 源端口   |
| DST   | 目的IP   |
| DPORT | 目的端口 |

## 具体实现

软件主要需要分为两部分，外部的GUI界面以及内部的嗅探功能。

目前容易上手且丰富美观的UI界面当属js阵营，可以结合css快速方便地构造出各种类型的外观。但js更多地是运行在浏览器里，写桌面软件在相关库以及性能方面不太理想。而我对于GUI软件的编写经验十分不足，因此选择了较为熟悉的python，搭配方便入门的PyQt。

python的一大优势在于异常丰富的第三方库，几乎囊括了我们想要的任何功能。Scapy是一款功能强大的包管理工具，可以发送、嗅探、读取、生成网络包。

图形界面负责软件的交互逻辑以及运行流程，嗅探功能获取到数据包并提供给相关运行部件，最终呈现给用户。

## 待改进

- tcp/ip报文的合并以及读取还未实现
- 高速流量下的性能问题，wireshark可以在本地流量很大的情况下使用的内存并不会猛增，有待研究使用了什么技术存储嗅探到的数据包

## 致谢

用户界面参考了[AntiSomnus](https://github.com/AntiSomnus)的项目[sniffer](https://github.com/AntiSomnus/sniffer)。