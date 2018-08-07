#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2013-2015 clowwindy
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

'''
一些公用的函数，涉及底层的header打包，地址判断，比较全面
'''

from __future__ import absolute_import, division, print_function, \
    with_statement

import socket
import struct
import logging
import hashlib
import hmac


ONETIMEAUTH_BYTES = 10
ONETIMEAUTH_CHUNK_BYTES = 12
ONETIMEAUTH_CHUNK_DATA_LEN = 2


def sha1_hmac(secret, data):
    return hmac.new(secret, data, hashlib.sha1).digest()


def onetimeauth_verify(_hash, data, key):
    return _hash == sha1_hmac(key, data)[:ONETIMEAUTH_BYTES]


def onetimeauth_gen(data, key):
    return sha1_hmac(key, data)[:ONETIMEAUTH_BYTES]

# 输入一个数字，返回对应的char符号
def compat_ord(s):
    if type(s) == int:
        return s
    return _ord(s)

# 输入一个数字，返回对应的char符号
def compat_chr(d):
    if bytes == str:
        return _chr(d)
    return bytes([d])


_ord = ord
_chr = chr
ord = compat_ord    # 输入char返回ascii
chr = compat_chr    # 输入ascii返回char

# 字符串在Python内部的表示是unicode编码，因此，在做编码转换时，通常需要以unicode作为中间编码
# 即先将其他编码的字符串解码（decode）成unicode，再从unicode编码（encode）成另一种编码。

# encode的作用是将unicode编码转换成其他编码的字符串
def to_bytes(s):
    if bytes != str:
        if type(s) == str:
            return s.encode('utf-8')
    return s

# decode的作用是将其他编码的字符串转换成unicode编码
def to_str(s):
    if bytes != str:
        if type(s) == bytes:
            return s.decode('utf-8')
    return s

# 将二进制地址转成点分形式的地址(v4 + v6)，而且返回的是utf-8格式的
# 含义：ntop就是 network to point点分形式
def inet_ntop(family, ipstr):
    if family == socket.AF_INET:
        # inet_aton()将一个字符串IP地址转换为一个32位的网络序列IP地址
        return to_bytes(socket.inet_ntoa(ipstr))
    elif family == socket.AF_INET6:
        import re
        # ':'.join() 读取一个列表，返回以“：”分隔的一个字符串
        # %02X 宽度2的十六进制格式化
        # lstrip()函数是移除前导字符，例如'0'
        # ipstr[::2]表示从第一个字母开始，读取每2个字符
        # zip函数返回一个tuple
        v6addr = ':'.join(('%02X%02X' % (ord(i), ord(j))).lstrip('0')
                          for i, j in zip(ipstr[::2], ipstr[1::2]))
        # re.sub()是替换函数，只替换一次：count=1
        v6addr = re.sub('::+', '::', v6addr, count=1)
        return to_bytes(v6addr)

# 将点分形式的ip转成二进制地址(v4 + v6)，返回的是二进制流
# 含义：pton就是 point点分形式 to network
def inet_pton(family, addr):
    addr = to_str(addr)
    if family == socket.AF_INET:
        # 将ipv4点分形式转成32位二进制地址。
        return socket.inet_aton(addr)
    elif family == socket.AF_INET6:
        if '.' in addr:  # a v4 addr
            # rindex()是查找字符串中的位置。
            v4addr = addr[addr.rindex(':') + 1:]
            v4addr = socket.inet_aton(v4addr)
            # map() return a list
            v4addr = map(lambda x: ('%02X' % ord(x)), v4addr)
            v4addr.insert(2, ':')
            newaddr = addr[:addr.rindex(':') + 1] + ''.join(v4addr)
            return inet_pton(family, newaddr)
        # 等价于[0,0,0,0,0,0,0,0]
        dbyts = [0] * 8  # 8 groups
        grps = addr.split(':')
        # 以下函数是功能忽略v6地址中的00:00之类的零
        # enumerate是返回一个迭代器，返回一个index和value of index
        for i, v in enumerate(grps):
            if v:
                dbyts[i] = int(v, 16)
            else:
                # grps[::-1]是字符串的反序
                for j, w in enumerate(grps[::-1]):
                    if w:
                        dbyts[7 - j] = int(w, 16)
                    else:
                        break
                break
        # 取出dbtys的每个元素的低8位，int是32位的
        return b''.join((chr(i // 256) + chr(i % 256)) for i in dbyts)
    else:
        raise RuntimeError("What family?")


def is_ip(address):
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            if type(address) != str:
                address = address.decode('utf8')
            inet_pton(family, address)
            return family
        except (TypeError, ValueError, OSError, IOError):
            pass
    return False

# 这个patch是干嘛的: 
# 判断python属性中是否有自带的ip地址格式转换函数。没有的话可以指定使用作者自定义的函数
def patch_socket():
    if not hasattr(socket, 'inet_pton'):
        socket.inet_pton = inet_pton

    if not hasattr(socket, 'inet_ntop'):
        socket.inet_ntop = inet_ntop


patch_socket()


ADDRTYPE_IPV4 = 0x01
ADDRTYPE_IPV6 = 0x04
ADDRTYPE_HOST = 0x03
ADDRTYPE_AUTH = 0x10
ADDRTYPE_MASK = 0xF

# 打包成shadowvpn的专用的地址header，追加到原数据头部。
def pack_addr(address):
    address_str = to_str(address)
    address = to_bytes(address)
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            # inet_pton：将“点分十进制” －> “二进制整数”
            r = socket.inet_pton(family, address_str)
            if family == socket.AF_INET6:
                # 把 ADDRTYPE_IPV6 = 4 封包到数据首部
                return b'\x04' + r
            else:
                # 把 ADDRTYPE_IPV4 = 1 封包到数据首部
                return b'\x01' + r
        except (TypeError, ValueError, OSError, IOError):
            pass
    if len(address) > 255:
        address = address[:255]  # TODO
    # 把 ADDRTYPE_HOST = 3 封包到数据首部
    return b'\x03' + chr(len(address)) + address


# add ss header
def add_header(address, port, data=b''):
    _data = b''
    _data = pack_addr(address) + struct.pack('>H', port) + data
    return _data

# 处理Shadowsocks专用的header，判断三种模式：ipv4 ipv6 hostname模式
# 返回四个值：地址类型，地址，端口，header长度
def parse_header(data):
    addrtype = ord(data[0])
    dest_addr = None
    dest_port = None
    header_length = 0
    if addrtype & ADDRTYPE_MASK == ADDRTYPE_IPV4:
        if len(data) >= 7:
            # ntoa: convert 32-bit packed binary format to string format
            dest_addr = socket.inet_ntoa(data[1:5])
            # 把端口数据打包为大端的c结构体
            dest_port = struct.unpack('>H', data[5:7])[0]
            header_length = 7
        else:
            logging.warn('header is too short')
    elif addrtype & ADDRTYPE_MASK == ADDRTYPE_HOST:
        if len(data) > 2:
            addrlen = ord(data[1])
            if len(data) >= 4 + addrlen:
                dest_addr = data[2:2 + addrlen]
                dest_port = struct.unpack('>H', data[2 + addrlen:4 +
                                                     addrlen])[0]
                header_length = 4 + addrlen
            else:
                logging.warn('header is too short')
        else:
            logging.warn('header is too short')
    elif addrtype & ADDRTYPE_MASK == ADDRTYPE_IPV6:
        if len(data) >= 19:
            dest_addr = socket.inet_ntop(socket.AF_INET6, data[1:17])
            dest_port = struct.unpack('>H', data[17:19])[0]
            header_length = 19
        else:
            logging.warn('header is too short')
    else:
        logging.warn('unsupported addrtype %d, maybe wrong password or '
                     'encryption method' % addrtype)
    if dest_addr is None:
        return None
    return addrtype, to_bytes(dest_addr), dest_port, header_length


class IPNetwork(object):
    ADDRLENGTH = {socket.AF_INET: 32, socket.AF_INET6: 128, False: 0}

    def __init__(self, addrs):
        self._network_list_v4 = []
        self._network_list_v6 = []
        if type(addrs) == str:
            addrs = addrs.split(',')
        list(map(self.add_network, addrs))

    def add_network(self, addr):
        if addr is "":
            return
        block = addr.split('/')
        addr_family = is_ip(block[0])
        addr_len = IPNetwork.ADDRLENGTH[addr_family]
        if addr_family is socket.AF_INET:
            ip, = struct.unpack("!I", socket.inet_aton(block[0]))
        elif addr_family is socket.AF_INET6:
            hi, lo = struct.unpack("!QQ", inet_pton(addr_family, block[0]))
            ip = (hi << 64) | lo
        else:
            raise Exception("Not a valid CIDR notation: %s" % addr)
        if len(block) is 1:
            prefix_size = 0
            while (ip & 1) == 0 and ip is not 0:
                ip >>= 1
                prefix_size += 1
            logging.warn("You did't specify CIDR routing prefix size for %s, "
                         "implicit treated as %s/%d" % (addr, addr, addr_len))
        elif block[1].isdigit() and int(block[1]) <= addr_len:
            prefix_size = addr_len - int(block[1])
            ip >>= prefix_size
        else:
            raise Exception("Not a valid CIDR notation: %s" % addr)
        if addr_family is socket.AF_INET:
            self._network_list_v4.append((ip, prefix_size))
        else:
            self._network_list_v6.append((ip, prefix_size))

    def __contains__(self, addr):
        addr_family = is_ip(addr)
        if addr_family is socket.AF_INET:
            ip, = struct.unpack("!I", socket.inet_aton(addr))
            return any(map(lambda n_ps: n_ps[0] == ip >> n_ps[1],
                           self._network_list_v4))
        elif addr_family is socket.AF_INET6:
            hi, lo = struct.unpack("!QQ", inet_pton(addr_family, addr))
            ip = (hi << 64) | lo
            return any(map(lambda n_ps: n_ps[0] == ip >> n_ps[1],
                           self._network_list_v6))
        else:
            return False


def test_inet_conv():
    ipv4 = b'8.8.4.4'
    b = inet_pton(socket.AF_INET, ipv4)
    assert inet_ntop(socket.AF_INET, b) == ipv4
    ipv6 = b'2404:6800:4005:805::1011'
    b = inet_pton(socket.AF_INET6, ipv6)
    assert inet_ntop(socket.AF_INET6, b) == ipv6


def test_parse_header():
    assert parse_header(b'\x03\x0ewww.google.com\x00\x50') == \
        (3, b'www.google.com', 80, 18)
    assert parse_header(b'\x01\x08\x08\x08\x08\x00\x35') == \
        (1, b'8.8.8.8', 53, 7)
    assert parse_header((b'\x04$\x04h\x00@\x05\x08\x05\x00\x00\x00\x00\x00'
                         b'\x00\x10\x11\x00\x50')) == \
        (4, b'2404:6800:4005:805::1011', 80, 19)


def test_pack_header():
    assert pack_addr(b'8.8.8.8') == b'\x01\x08\x08\x08\x08'
    assert pack_addr(b'2404:6800:4005:805::1011') == \
        b'\x04$\x04h\x00@\x05\x08\x05\x00\x00\x00\x00\x00\x00\x10\x11'
    assert pack_addr(b'www.google.com') == b'\x03\x0ewww.google.com'


def test_ip_network():
    ip_network = IPNetwork('127.0.0.0/24,::ff:1/112,::1,192.168.1.1,192.0.2.0')
    assert '127.0.0.1' in ip_network
    assert '127.0.1.1' not in ip_network
    assert ':ff:ffff' in ip_network
    assert '::ffff:1' not in ip_network
    assert '::1' in ip_network
    assert '::2' not in ip_network
    assert '192.168.1.1' in ip_network
    assert '192.168.1.2' not in ip_network
    assert '192.0.2.1' in ip_network
    assert '192.0.3.1' in ip_network  # 192.0.2.0 is treated as 192.0.2.0/23
    assert 'www.google.com' not in ip_network


if __name__ == '__main__':
    test_inet_conv()
    test_parse_header()
    test_pack_header()
    test_ip_network()
