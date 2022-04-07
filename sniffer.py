from scapy.config import conf
from scapy.interfaces import ifaces
from scapy.layers.inet import icmptypes
from scapy.sendrecv import sniff, AsyncSniffer
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtGui import QFont
from PyQt5.QtCore import QThread, Qt, pyqtSignal, QObject
from PyQt5.QtWidgets import QFrame, QAbstractItemView, QSplitter, \
    QMainWindow, QWidget, QTableWidget, \
    QTableWidgetItem, QProxyStyle, QStyle

import sys
import logging

import os
from packet_r import Packet_r, igmptypes, arpoptypes

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
regex = "((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[" \
        "0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1," \
        "4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1," \
        "4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){" \
        "3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[" \
        "1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1," \
        "4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){" \
        "3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[" \
        "0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{" \
        "1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[" \
        "1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[" \
        "1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$)) "


class Style(QProxyStyle):
    """A new style class derived from QProxyStyle.
    Make the tablewidget no dotted line without sacrificing the control by keyboard
    """

    def drawPrimitive(self, element, option, painter, widget):
        if element == QStyle.PE_FrameFocusRect:
            return
        super().drawPrimitive(element, option, painter, widget)


class SnifferWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.start = False
        self.packets = []
        self.num = 0
        self.interfaces = self.get_interfaces()

        self.worker = None
        self.thread = None

        self.resize(850, 800)

        main_frame = QWidget()
        self.setCentralWidget(main_frame)

        grid_layout = QtWidgets.QGridLayout()
        grid_layout.setContentsMargins(0, 0, 0, 0)

        v_layout = QtWidgets.QVBoxLayout(main_frame)
        v_layout.addLayout(grid_layout)

        # NIC Label
        self.label_NIC = QtWidgets.QLabel(main_frame)
        self.label_NIC.setText("NIC")
        self.label_NIC.setFont(QFont('Consolas', 11, QFont.Bold))

        # NIC comboBox
        self.comboBox = QtWidgets.QComboBox(main_frame)
        self.comboBox.setFont(QFont('Consolas', 10, QFont.Light))
        # add interface name into comboBox
        for i in self.get_interfaces().keys():
            self.comboBox.addItem(i)

        grid_layout.addWidget(self.label_NIC, 0, 0, 1, 1)
        grid_layout.addWidget(self.comboBox, 0, 1, 1, 8)

        # protocol label
        label_pro = QtWidgets.QLabel(main_frame)
        label_pro.setFont(QFont('Consolas', 11, QFont.Bold))
        label_pro.setText("PRO")

        # source address label
        label_src = QtWidgets.QLabel(main_frame)
        label_src.setFont(QFont('Consolas', 11, QFont.Bold))
        label_src.setText("SRC")

        # source port label
        label_sport = QtWidgets.QLabel(main_frame)
        label_sport.setFont(QFont('Consolas', 11, QFont.Bold))
        label_sport.setText("SPORT")

        # destination address label
        label_dst = QtWidgets.QLabel(main_frame)
        label_dst.setFont(QFont('Consolas', 11, QFont.Bold))
        label_dst.setText("DST")

        # destination port label
        label_dport = QtWidgets.QLabel(main_frame)
        label_dport.setFont(QFont('Consolas', 11, QFont.Bold))
        label_dport.setText("DPORT")

        # protocol LineEdit
        self.pro = QtWidgets.QLineEdit(main_frame)
        self.pro.setFont(QFont('Consolas', 10, QFont.Light))
        # 协议自动补全
        completer = QtWidgets.QCompleter(
            ["ip", "ip6", "tcp", "udp", "arp", "icmp", "icmp6", "igmp"])
        completer.popup().setFont(QFont('Consolas', 10, QFont.Light))
        self.pro.setCompleter(completer)

        # src LineEdit
        self.src = QtWidgets.QLineEdit(main_frame)
        self.src.setFont(QFont('Consolas', 10, QFont.Light))
        v = QtGui.QRegExpValidator(QtCore.QRegExp(regex))
        self.src.setValidator(v)

        # sport LineEdit
        self.sport = QtWidgets.QLineEdit(main_frame)
        self.sport.setFont(QFont('Consolas', 10, QFont.Light))
        self.sport.setValidator(QtGui.QIntValidator(0, 65535))

        # dst LineEdit
        self.dst = QtWidgets.QLineEdit(main_frame)
        self.dst.setFont(QFont('Consolas', 10, QFont.Light))
        self.dst.setValidator(v)

        # dport LineEdit
        self.dport = QtWidgets.QLineEdit(main_frame)
        self.dport.setFont(QFont('Consolas', 10, QFont.Light))
        self.dport.setValidator(QtGui.QIntValidator(0, 65535))

        '''2nd line layout'''
        grid_layout.addWidget(label_pro, 1, 0, 1, 1)
        grid_layout.addWidget(self.pro, 1, 1, 1, 1)
        grid_layout.addWidget(label_src, 1, 2, 1, 1)
        grid_layout.addWidget(self.src, 1, 3, 1, 1)
        grid_layout.addWidget(label_sport, 1, 4, 1, 1)
        grid_layout.addWidget(self.sport, 1, 5, 1, 1)
        grid_layout.addWidget(label_dst, 1, 6, 1, 1)
        grid_layout.addWidget(self.dst, 1, 7, 1, 1)
        grid_layout.addWidget(label_dport, 1, 8, 1, 1)
        grid_layout.addWidget(self.dport, 1, 9, 1, 1)

        '''3rd line'''
        # start/stop button
        self.button = QtWidgets.QPushButton(main_frame)
        self.button.setText("START")
        self.button.setFont(QFont('Consolas', 10, QFont.Light))
        self.button.clicked.connect(self.evt_start)
        self.button.setFont(QFont('Consolas', 11, QFont.Light))
        self.button.setFixedHeight(30)
        # combine searchbutton and search icon into a HBoxLayout
        hbox = QtWidgets.QHBoxLayout()
        hbox.setContentsMargins(0, 0, 0, 0)
        hbox.setSpacing(0)

        '''3nd line layout'''
        grid_layout.addLayout(hbox, 2, 0, 1, 10)
        grid_layout.addWidget(self.button, 0, 9, 1, 1)

        """table """
        self.tableWidget = QTableWidget(main_frame)
        self.tableWidget.verticalHeader().setDefaultSectionSize(25)
        self.tableWidget.horizontalHeader().setFont(QFont('Consolas', 11, QFont.Light))
        self.tableWidget.setSizeAdjustPolicy(
            QtWidgets.QAbstractScrollArea.AdjustToContents)

        # No border when focus
        self.tableWidget.setStyle(Style())
        self.tableWidget.setStyleSheet(" QTableWidget {outline: 0;}")
        self.tableWidget.setMinimumHeight(50)
        self.tableWidget.setColumnCount(5)
        self.tableWidget.verticalHeader().setVisible(False)
        self.tableWidget.horizontalHeader().setDefaultAlignment(Qt.AlignLeft)
        self.tableWidget.setHorizontalHeaderLabels(
            ['No.', 'Source address', 'Destination address', 'Length', 'Protocol'])
        self.tableWidget.setColumnWidth(0, 60)
        self.tableWidget.setColumnWidth(1, 290)
        self.tableWidget.setColumnWidth(2, 290)
        self.tableWidget.setColumnWidth(3, 75)
        self.tableWidget.setColumnWidth(4, 90)
        self.tableWidget.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # set every column resizes automatically to fill remaining spaces
        self.tableWidget.horizontalHeader().setStretchLastSection(True)
        self.tableWidget.setShowGrid(False)
        self.tableWidget.setFont(QFont('Consolas', 10, QFont.Light))
        self.tableWidget.itemSelectionChanged.connect(self.evt_select)
        # select a row when clicking
        self.tableWidget.setSelectionBehavior(QTableWidget.SelectRows)
        self.tableWidget.setMouseTracking(True)

        """tab1"""
        self.tabWidget = QtWidgets.QTabWidget(main_frame)
        self.tabWidget.setMinimumHeight(50)
        self.tabWidget.setFont(QFont('Consolas', 10, QFont.Light))
        """tab2"""
        self.tabWidget_2 = QtWidgets.QTabWidget(main_frame)
        self.tabWidget_2.setMinimumHeight(50)
        self.tabWidget_2.setFont(QFont('Consolas', 10, QFont.Light))

        """split window"""

        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self.tableWidget)
        splitter.addWidget(self.tabWidget)
        splitter.addWidget(self.tabWidget_2)
        splitter.setSizes([232, 225, 225])

        grid_layout.addWidget(splitter, 3, 0, 5, 10)
        grid_layout.setRowMinimumHeight(3, 690)

        self.setWindowTitle('Sniffer')
        QtCore.QMetaObject.connectSlotsByName(self)

    def get_filter(self):
        f = ""
        if self.pro.text():
            f += " and " + self.pro.text()
        elif self.src.text():
            f += f" and src {self.src.text()}"
        elif self.dst.text():
            f += f" and dst {self.dst.text()}"
        elif self.sport.text():
            f += f" and src port {self.sport.text()}"
        elif self.dport.text():
            f += f" and src port {self.dport.text()}"
        f = f[5:].lower()

        return f

    def get_current_interface(self):
        return self.interfaces[self.comboBox.currentText()] if self.interfaces else None

    def get_interfaces(self):
        return {v.name: v for k, v in ifaces.items()}

    def evt_start(self):
        """Event when Start button changes.
        The event for clicking the Start/Stop button, which is to start/stop the progress.
        At the same time, set window's title accordingly
        """
        self.start = not self.start

        if self.start:
            self.button.setText('Stop')

            self.thread = QThread()
            self.worker = Sniffer(flt=self.get_filter(), iface=self.get_current_interface())
            self.worker.moveToThread(self.thread)

            self.thread.started.connect(self.worker.run)

            self.worker.addPacket.connect(self.add_packet_to_table)
            self.worker.scrollEnd.connect(self.scroll_end)
            self.worker.finished.connect(self.thread.quit)
            self.worker.finished.connect(self.worker.deleteLater)
            self.worker.finished.connect(lambda: self.button.setText('Start'))
            self.thread.finished.connect(self.thread.deleteLater)

            self.thread.start()
        else:
            self.worker.finish()

    def evt_select(self):
        """Event when select a row(packet).
        The event for selecting a row(packet), which is to show detailed and
        reassembly information about the chosen packet.
        """
        QtCore.QCoreApplication.processEvents()

        for i in self.tableWidget.selectedItems():
            row = i.row()

        for i in range(self.tabWidget.count()):
            self.tabWidget.removeTab(0)

        for i in range(self.tabWidget_2.count()):
            self.tabWidget_2.removeTab(0)

        count = self.tabWidget.count()

        pkt = self.packets[row]
        layers = pkt.packet_to_layerlist()

        # single packet infomation
        for i in layers:
            QtCore.QCoreApplication.processEvents()
            s = f"No. {row}\n" + i[0] + "\n"
            for key in i[1]:
                if key == 'type' and i[0] == 'ICMP':
                    s = s + \
                        "%-10s%s\n" % ((key[0].upper() + key[1:] + ":"),
                                       str(i[1][key]) + ' (' + icmptypes[int(i[1][key])] + ')')
                elif key == 'op' and i[0] == 'ARP':
                    s = s + \
                        "%-10s%s\n" % ((key[0].upper() + key[1:] + ":"), str(
                        i[1][key]) + ' (' + arpoptypes[int(i[1][key])] + ')')
                elif key == 'type' and i[0] == 'IGMP':
                    s = s + \
                        "%-10s%s\n" % ((key[0].upper() + key[1:] + ":"),
                                       str(i[1][key]) + ' (' + igmptypes[int(i[1][key])] + ')')
                else:
                    s = s + \
                        "%-10s%s\n" % ((key[0].upper() +
                                        key[1:] + ":"), i[1][key])

            self.create_tab(self.tabWidget, i[0], s)

        self.create_tab(self.tabWidget_2, "Whole in hex",
                        pkt.hexdump())

        try:
            s = ""
            s = s + "No. " + str(count) + "\n" + i[0] + "\n"
            self.create_tab(self.tabWidget2, "Load in UTF-8",
                            s + "Decoded by UTF-8:\n" + pkt.packet_to_load_utf8())
            self.create_tab(self.tabWidget2, "Load in GB2312",
                            s + "Decoded by GB2312:\n" + pkt.packet_to_load_gb())
        except:  # no load or decode error
            pass

    def scroll_end(self):
        self.tableWidget.scrollToBottom()

    def add_packet_to_table(self, pkt):
        self.packets.append(pkt)
        message = [str(self.num)] + pkt.packet_to_info()
        self.tableWidget.insertRow(self.num)
        for i in range(5):
            item = QTableWidgetItem(message[i])
            self.tableWidget.setItem(self.num, i, item)
        self.num += 1

    def create_tab(self, tab, title, content):
        """Create a new tab when requirement is given.
        Args:
            tab: the tab that the text display
            title: the title of the tab
            content: the content
        """
        a = QtWidgets.QTextBrowser()
        a.setFrameStyle(QFrame.NoFrame)
        a.setText(content)
        a.setFont(QFont('Consolas', 10, QFont.Light))
        tab.addTab(a, title)


class Sniffer(QObject):
    scrollEnd = pyqtSignal()
    addPacket = pyqtSignal(Packet_r)
    finished = pyqtSignal()

    def __init__(self, iface=None, flt=None):
        super().__init__()
        self.iface = iface
        self.filter = flt
        self.start = True
        self.scroll = True
        self.t = None

    def run(self):
        if self.filter:
            self.t = AsyncSniffer(iface=self.iface, filter=self.filter, prn=self.process_packet)
        else:
            self.t = AsyncSniffer(iface=self.iface, prn=self.process_packet)
        self.t.start()

    def finish(self):
        if self.t:
            self.t.stop()
            self.t.join()
            self.finished.emit()

    def toggle_scroll(self):
        self.scroll = not self.scroll

    def process_packet(self, pkt):
        pkt = Packet_r(pkt)
        self.addPacket.emit(pkt)
        if self.scroll:
            self.scrollEnd.emit()


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    w = SnifferWindow()
    w.show()
    app.exec_()
