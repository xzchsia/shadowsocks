#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2014-2015 clowwindy
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
dns处理
dns协议文档rfc1035：
http://www.ccs.neu.edu/home/amislove/teaching/cs4700/fall09/handouts/project1-primer.pdf
'''

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import socket
import struct
import re
import logging

from shadowsocks import common, lru_cache, eventloop, shell


CACHE_SWEEP_INTERVAL = 30

# 该正则表达式意思如下：
# 零宽度正预测先行断言(?=表达式) 
# 匹配26个字母，还有数字，横线-
# 重复[1,63)次。
# 负向零宽后发断言(?<!表达式)，匹配
# 锚点：末尾
# 来自：http://stackoverflow.com/questions/2532053/validate-a-hostname-string
VALID_HOSTNAME = re.compile(br"(?!-)[A-Z\d\-_]{1,63}(?<!-)$", re.IGNORECASE)
# 使用正则表达式的complie能更高效率。在匹配成千上万个字符串时候，使用complie函数速度更快

common.patch_socket()

# rfc1035
# format rfc1035定义：DNSformat
# +---------------------+
# |        Header       |
# +---------------------+
# |       Question      | the question for the name server
# +---------------------+
# |        Answer       | RRs answering the question
# +---------------------+
# |      Authority      | RRs pointing toward an authority
# +---------------------+
# |      Additional     | RRs holding additional information
# +---------------------+
#
# header
# header数据格式
# 这里一行16个位，就是两个字节
#                                 1  1  1  1  1  1
#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      ID                       |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    QDCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ANCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    NSCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ARCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

QTYPE_ANY = 255 
QTYPE_A = 1    # A记录：WEB服务器的IP指向
QTYPE_AAAA = 28    # IPV6解析记录
QTYPE_CNAME = 5    # CNAME (Canonical Name)记录，通常称别名解析
QTYPE_NS = 2    # NS（Name Server）记录是域名服务器记录
QCLASS_IN = 1    # 规定就是0x01

# 构造dns请求的目标hostname，返回一个二进制流
# 对每逗号前的字符串打包一次，append进result
def build_address(address):
    # strip()删除序列是只要边（开头或结尾）上的字符在删除序列内，就删除掉
    address = address.strip(b'.')
    labels = address.split(b'.')
    results = []
    for label in labels:
        l = len(label)
        if l > 63:    # hostname太长
            return None
        # result分别追加数据：逐级域名的长度，逐级域名的字符串
        results.append(common.chr(l))
        results.append(label)
    results.append(b'\0')
    return b''.join(results)

# rfc1035
# dns questions
#                                 1  1  1  1  1  1
#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      QNAME                    | -- a sequence of labels, where each label consists of a length octet followed by that number of octets.
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      QTYPE                    | -- 前面已经定义的QTYPE_A。。等
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      QCLASS                   | -- 0x01
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# 构造一个dns查询的DNS QuestionS请求。
# 参数：address为域名，qtype为查询类型，id为查询id
def build_request(address, qtype):
    request_id = os.urandom(2)
	# pack的‘！’表示结构体打包为网络顺序
    header = struct.pack('!BBHHHH', 1, 0, 1, 0, 0, 0)
    addr = build_address(address)
    qtype_qclass = struct.pack('!HH', qtype, QCLASS_IN)
    return request_id + header + addr + qtype_qclass

# 分析ip数据包，返回一个ip地址，点分格式
# TODO 参数：data是什么类型
def parse_ip(addrtype, data, length, offset):
    if addrtype == QTYPE_A:
#         htons() host to network short
#         htonl() host to network long
#         ntohs() network to host short
#         ntohl() network to host long
#         转换32位打包的IPV4地址为IP地址的标准点号分隔字符串表示。
#         socket.inet_ntop(address_family,packed_ip)
#         转换IP地址字符串为打包二进制格式。地址家族为AF_INET和AF_INET6，它们分别表示IPV4和IPV6。
#         socket.inet_pton(address_family,ip_string)
        return socket.inet_ntop(socket.AF_INET, data[offset:offset + length])
    elif addrtype == QTYPE_AAAA:
        return socket.inet_ntop(socket.AF_INET6, data[offset:offset + length])
    elif addrtype in [QTYPE_CNAME, QTYPE_NS]:
        return parse_name(data, offset)[1]
    else:
        return data[offset:offset + length]


# 这里面涉及到DNS压缩指针的实现，参考rfc1035的“DNS Packet Compression”
# 例如，域名F.ISI.ARPA 和 FOO.F.ISI.ARPA 和 ARPA 可以打包为如下数据QNAME流（忽略其他报文段）
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# O  +                    +                       +
# F  +                    +                       +
# F  +                    +                       +
# S  +     BYTE0          +        BYTE1          +
# E  +                    +                       +
# T  +                    +                       +
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# 20 |         1          |            F          |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# 22 |         3          |            I          |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# 24 |         S          |            I          |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# 26 |         4          |            A          |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# 28 |         R          |            P          |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# 30 |         A          |            0          |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# ......
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# 40 |         3          |            F          |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# 42 |         0          |            0          |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# 44 | 1 1 |                 20                   |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# ......
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# 64 | 1 1 |                 26                   |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

# 处理dns的Qname报文，返回一个元组（长度，别名）的二进制流，遇到压缩指针则递归
def parse_name(data, offset):
    p = offset
    labels = []
    # l为data数据流中的偏置offset的label的长度
    l = common.ord(data[p])
    while l > 0:
        # 为什么是128+64, 因为未经压缩的合法name长度在63内，因此
        # rfc定义0x11000000B为压缩指针的标志
        if (l & (128 + 64)) == (128 + 64):
            # pointer,取出指针的位置
            pointer = struct.unpack('!H', data[p:p + 2])[0]
            # 指针取两个字节减去高两位（用于标志0x11000000B那两位）
            pointer &= 0x3FFF
            # 递归处理指针，找到上文的name记录，参考rfc1035
            r = parse_name(data, pointer)
            # 读取指针所指的数据，追加到labels中
            labels.append(r[1])
            # 指针偏移自增两个字节（跳过0x11000000B所在的两个字节的data数据段）
            p += 2
            # pointer is the end,递归返回
            return p - offset, b'.'.join(labels)
        # 若不是指针压缩，直接追加dns报文
        else:
            # 追加labels
            labels.append(data[p + 1:p + 1 + l])
            # 指针自增（1+len）
            p += 1 + l
        l = common.ord(data[p])
    # 递归返回
    return p - offset + 1, b'.'.join(labels)


# rfc1035
# record答复
# A dns answer has the following format:
#                                    1  1  1  1  1  1
#      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                                               |
#    /                                               /
#    /                      NAME                     / -- The domain name that was queried
#    |                                               |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                      TYPE                     | -- A/AAAA/NS, etc
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                     CLASS                     | -- Two octets which specify the class of the data in the RDATA field
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                      TTL                      | -- The number of seconds the results can be cached
#    |                                               |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                   RDLENGTH                    | -- The length of the RDATA field
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
#    /                     RDATA                     / -- The data of the response
#    /                                               /
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# 处理dns记录
# 返回长度，元组（域名，ip，类型，class，ttl）
# 形参的offset难以理解。
def parse_record(data, offset, question=False):
    nlen, name = parse_name(data, offset)
    if not question:
        record_type, record_class, record_ttl, record_rdlength = struct.unpack(
            '!HHiH', data[offset + nlen:offset + nlen + 10]
        )
        ip = parse_ip(record_type, data, record_rdlength, offset + nlen + 10)
        return nlen + 10 + record_rdlength, \
            (name, ip, record_type, record_class, record_ttl)
    else:
        record_type, record_class = struct.unpack(
            '!HH', data[offset + nlen:offset + nlen + 4]
        )
        return nlen + 4, (name, None, record_type, record_class, None, None)


# DNS packets have a header that is shown below:

#                                 1  1  1  1  1  1
#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      ID                       |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    QDCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ANCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    NSCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ARCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

# 处理header的函数，返回rcf1035各组的原始数据。
def parse_header(data):
    if len(data) >= 12:
        header = struct.unpack('!HBBHHHH', data[:12])
        res_id = header[0]
        res_qr = header[1] & 128    # 0x80
        res_tc = header[1] & 2    # 0x02
        res_ra = header[2] & 128    # 0x80
        res_rcode = header[2] & 15    # 0x0F
        # assert res_tc == 0
        # assert res_rcode in [0, 3]
        res_qdcount = header[3]
        res_ancount = header[4]
        res_nscount = header[5]
        res_arcount = header[6]
        return (res_id, res_qr, res_tc, res_ra, res_rcode, res_qdcount,
                res_ancount, res_nscount, res_arcount)
    return None

# 处理答复
def parse_response(data):
    try:
        if len(data) >= 12:
            header = parse_header(data)
            if not header:
                return None
            res_id, res_qr, res_tc, res_ra, res_rcode, res_qdcount, \
                res_ancount, res_nscount, res_arcount = header
            
            # qds是啥
            qds = []
            ans = []
            offset = 12
            # QDCOUNT an unsigned 16 bit integer specifying the number of entries in the question section.
            # You should set this field to 1, indicating you have one question.
            for i in range(0, res_qdcount):
                l, r = parse_record(data, offset, True)
                offset += l
                if r:
                    qds.append(r)
            # ANCOUNT an unsigned 16 bit integer specifying the number of resource records in the answer section.
            # You should set this field to 0, indicating you are not providing any answers.
            for i in range(0, res_ancount):
                l, r = parse_record(data, offset)
                offset += l
                if r:
                    ans.append(r)
            # NSCOUNT an unsigned 16 bit integer specifying the number of name server resource records in the authority records section. 
            # You should set this field to 0, and should ignore any response entries in this section.
            for i in range(0, res_nscount):
                l, r = parse_record(data, offset)
                offset += l
            # ARCOUNT an unsigned 16 bit integer specifying the number of resource records in the additional
            # records section. You should set this field to 0, and should ignore any response entries in this section.
            for i in range(0, res_arcount):
                l, r = parse_record(data, offset)
                offset += l
            # 新建response实例,返回一个实例
            response = DNSResponse()
            if qds:
                response.hostname = qds[0][0]
            for an in qds:
                response.questions.append((an[1], an[2], an[3]))
            for an in ans:
                response.answers.append((an[1], an[2], an[3]))
            return response
    except Exception as e:
        shell.print_exception(e)
        return None


# 是否一个有效主机名
def is_valid_hostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == b'.':
        hostname = hostname[:-1]
    # VALID_HOSTNAME实例是一个re表达式。在本文件的顶部有声明，用于判读有效主机
    # 该表达式是clowwidny从stackflow爬下来的。。。
    return all(VALID_HOSTNAME.match(x) for x in hostname.split(b'.'))


class DNSResponse(object):
    def __init__(self):
        self.hostname = None
        self.questions = []  # each: (addr, type, class)
        self.answers = []  # each: (addr, type, class)

    def __str__(self):
        return '%s: %s' % (self.hostname, str(self.answers))


STATUS_FIRST = 0
STATUS_SECOND = 1


class DNSResolver(object):

    def __init__(self, server_list=None, prefer_ipv6=False):
        self._loop = None
        self._hosts = {}
        self._hostname_status = {}
        # --------------------------------------------------
        # hostname to callback 和 callback to hostname有什么区别>>>>参考本文件末尾的def resolve函数。
        # hostname to callback就是每一个hostname对应一个回调函数
        # 若多个函数对应相同的hostname，只需向远端发起一次dns请求，减少重复查询
        # 删除重复键值(key=hostname,value=callback)的操作不需要人为干预，字典完成这个功能（key不允许重复）
        self._hostname_to_cb = {}
        # --------------------------------------------------
        # callback to hostname就是一个回调函数对应一个hostname
        # 一个hostname有可能是由多个进程调用查询dns的。因此回朔时候也要逐个返回。
        self._cb_to_hostname = {}
        # --------------------------------------------------
        # todo : 阅lrucache的源码
        self._cache = lru_cache.LRUCache(timeout=300)
        self._sock = None
        if server_list is None:
            self._servers = None
            self._parse_resolv()
        else:
            self._servers = server_list
        if prefer_ipv6:
            self._QTYPES = [QTYPE_AAAA, QTYPE_A]
        else:
            self._QTYPES = [QTYPE_A, QTYPE_AAAA]
        self._parse_hosts()
        # TODO monitor hosts change and reload hosts
        # TODO parse /etc/gai.conf and follow its rules

    # 从linux中读取dns地址，加入类DnsResolve的解析服务器列表中
    def _parse_resolv(self):
        self._servers = []
        try:
            with open('/etc/resolv.conf', 'rb') as f:
                content = f.readlines()
                for line in content:
                    # strip() returns a copy of the string with leading whitespace removed.
                    line = line.strip()
                    if not (line and line.startswith(b'nameserver')):
                        continue

                    parts = line.split()
                    if len(parts) < 2:
                        continue

                    server = parts[1]
                    if common.is_ip(server) == socket.AF_INET:
                        if type(server) != str:
                            server = server.decode('utf8')
                        self._servers.append(server)
        except IOError:
            pass
        if not self._servers:
            # 系统没有指定dns，就用谷歌的
            self._servers = ['8.8.4.4', '8.8.8.8']

    # 自定义的域名解析，即hosts文件，添加到类的hosts列表中（字典）
    def _parse_hosts(self):
        etc_path = '/etc/hosts'
        # windows用户
        if 'WINDIR' in os.environ:
            etc_path = os.environ['WINDIR'] + '/system32/drivers/etc/hosts'
        try:
            with open(etc_path, 'rb') as f:
                for line in f.readlines():
                    line = line.strip()
                    parts = line.split()
                    if len(parts) < 2:
                        continue

                    ip = parts[0]
                    if not common.is_ip(ip):
                        continue

                    for i in range(1, len(parts)):
                        hostname = parts[i]
                        if hostname:
                            self._hosts[hostname] = ip
        except IOError:
            self._hosts['localhost'] = '127.0.0.1'

    # 添加到事件循环中
    def add_to_loop(self, loop):
        # 防止重复loop
        if self._loop:
            raise Exception('already add to loop')
        self._loop = loop
        # TODO when dns server is IPv6
        # 新建一个socket实例，为udp查询类型
        # SOCK_DGRAM 是无保障的面向消息的socket， 主要用于在网络上发广播信息。(基于UDP的)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                   socket.SOL_UDP)
        # dnsserver只作为发送请求的一个东西，是客户端，应该是client，所以没bind
        # 非阻塞
        self._sock.setblocking(False)
        # 把socket加到loop里面，事件触发类型：有数据可读
        loop.add(self._sock, eventloop.POLL_IN, self)
        # 这里加入了handler，eventloop检测到socket有“动静”时调用self.handle_events
        loop.add_periodic(self.handle_periodic)

    # 这里触发回调：查找某个hostname对应的回调函数
    # 回调是上一级函数调用查询dns的，因此需要回朔。
    # 看了好多次，扔看不懂什么工作原理。。认为它字典是唯一的会漏掉某些键值。
    def _call_callback(self, hostname, ip, error=None):
        # 这里取出我们在请求的同时放进字典里面的callback函数
        # cb = callback
        callbacks = self._hostname_to_cb.get(hostname, [])    # 寻找一个键为hostname的一个callback函数，实际上只能返回一个，而不是callbacks。
        for callback in callbacks:
            # 判断hostname是否已经被回调，已回调则删掉等待回调的字典对应键对。避免重复查询dns
            if callback in self._cb_to_hostname:
                del self._cb_to_hostname[callback]
            if ip or error:
                # 实际调用发送数据的同时注册的回调函数callback to host
                callback((hostname, ip), error)
            else:
                callback((hostname, None),
                         Exception('unknown hostname %s' % hostname))
        # 回调完，删除键值 hostname to callback 包括反过来。
        if hostname in self._hostname_to_cb:
            del self._hostname_to_cb[hostname]
        if hostname in self._hostname_status:
            del self._hostname_status[hostname]

    # 服务函数，放进loop事件中。
    def _handle_data(self, data):
        response = parse_response(data)
        if response and response.hostname:
            hostname = response.hostname
            ip = None
            # 从dns报文里面拿到ip地址，只取出一个记录，就break掉了
            for answer in response.answers:
                if answer[1] in (QTYPE_A, QTYPE_AAAA) and \
                        answer[2] == QCLASS_IN:
                    ip = answer[0]
                    break
            # 若没有解析到ip，则从hostname_status字典中取出该hostname对应的域名类型
            # 若ip无效，且域名记录类型是v6,发送查询dns，以AAAA类型。
            if not ip and self._hostname_status.get(hostname, STATUS_SECOND) \
                    == STATUS_FIRST:
                self._hostname_status[hostname] = STATUS_SECOND
                self._send_req(hostname, self._QTYPES[1])
            else:
                if ip:
                    self._cache[hostname] = ip
                    self._call_callback(hostname, ip)
                elif self._hostname_status.get(hostname, None) \
                        == STATUS_SECOND:
                    for question in response.questions:
                        if question[1] == self._QTYPES[1]:
                            self._call_callback(hostname, None)
                            break
    # 事件服务函数
    def handle_event(self, sock, fd, event):
            # 看是不是自己socket的，因为dns，tcp，udp的server都分别有自己的socket
        if sock != self._sock:
            return
            # 若出错了，销毁socket并重新注册一个。
        if event & eventloop.POLL_ERR:
            logging.error('dns socket err')
            self._loop.remove(self._sock)
            self._sock.close()
            # TODO when dns server is IPv6
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                       socket.SOL_UDP)
            self._sock.setblocking(False)
            self._loop.add(self._sock, eventloop.POLL_IN, self)
        else:
        	# 因为是dns基于udp报文，所以没有连接要处理
            data, addr = sock.recvfrom(1024)
            if addr[0] not in self._servers:
                logging.warn('received a packet other than our dns')
                return
            self._handle_data(data)

    def handle_periodic(self):
        self._cache.sweep()

    def remove_callback(self, callback):
        hostname = self._cb_to_hostname.get(callback)
        if hostname:
            del self._cb_to_hostname[callback]
            arr = self._hostname_to_cb.get(hostname, None)
            if arr:
                arr.remove(callback)
                if not arr:
                    del self._hostname_to_cb[hostname]
                    if hostname in self._hostname_status:
                        del self._hostname_status[hostname]

    # 发送dns请求
    def _send_req(self, hostname, qtype):
        req = build_request(hostname, qtype)
        for server in self._servers:
            logging.debug('resolving %s with type %d using server %s',
                          hostname, qtype, server)
            # 向远端服务器查询dns
            self._sock.sendto(req, (server, 53))

    # 解析dns函数。被tcprelay模块调用。
    # callback对应一个上一级的事件循环函数
    def resolve(self, hostname, callback):    # 在tcprelay模块中，callback函数指向tcp类的_handle_dns_resolved()
        # hostname是否是字节码
        if type(hostname) != bytes:
            hostname = hostname.encode('utf8')
        if not hostname:
            callback(None, Exception('empty hostname'))
        elif common.is_ip(hostname):
            # 先看是不是一个ip，是就不用解析了，直接调用callback
            callback((hostname, hostname), None)
        elif hostname in self._hosts:
            # 看是不是在host文件里面，是就直接callback
            logging.debug('hit hosts: %s', hostname)
            ip = self._hosts[hostname]
            callback((hostname, ip), None)
        elif hostname in self._cache:
            # 看是不是在cache里面，是就直接callback
            logging.debug('hit cache: %s', hostname)
            ip = self._cache[hostname]
            callback((hostname, ip), None)
        # 以上条件都不满足，开始进行解析dns
        else:
            if not is_valid_hostname(hostname):
                callback(None, Exception('invalid hostname: %s' % hostname))
                return
            arr = self._hostname_to_cb.get(hostname, None)
            # 在host_to_callback中检查是否有记录
            if not arr:
                self._hostname_status[hostname] = STATUS_FIRST
                self._send_req(hostname, self._QTYPES[0])
                # 同时在_hostname_to_cb注册一个{hostname:callback}的一对
                # 要hostname因为这个socket可以发出去很多不同hostname的解析请求
                self._hostname_to_cb[hostname] = [callback]
                self._cb_to_hostname[callback] = hostname
            else:
                arr.append(callback)
                # TODO send again only if waited too long
                self._send_req(hostname, self._QTYPES[0])

    def close(self):
        if self._sock:
            if self._loop:
                self._loop.remove_periodic(self.handle_periodic)
                self._loop.remove(self._sock)
            self._sock.close()
            self._sock = None


def test():
    dns_resolver = DNSResolver()
    loop = eventloop.EventLoop()
    dns_resolver.add_to_loop(loop)

    global counter
    counter = 0

    def make_callback():
        global counter

        def callback(result, error):
            global counter
            # TODO: what can we assert?
            print(result, error)
            counter += 1
            # 下文测试样例就是9个，可以自己修改
            if counter == 9:
                dns_resolver.close()
                loop.stop()
        a_callback = callback
        return a_callback

    assert(make_callback() != make_callback())

    dns_resolver.resolve(b'google.com', make_callback())
    dns_resolver.resolve('google.com', make_callback())
    dns_resolver.resolve('example.com', make_callback())
    dns_resolver.resolve('ipv6.google.com', make_callback())
    dns_resolver.resolve('www.facebook.com', make_callback())
    dns_resolver.resolve('ns2.google.com', make_callback())
    dns_resolver.resolve('invalid.@!#$%^&$@.hostname', make_callback())
    dns_resolver.resolve('toooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'long.hostname', make_callback())
    dns_resolver.resolve('toooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'long.hostname', make_callback())

    loop.run()


if __name__ == '__main__':
    test()
