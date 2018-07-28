#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2015 clowwindy
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

from __future__ import absolute_import, division, print_function, \
    with_statement

import sys
import os
import logging
import signal

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../'))
from shadowsocks import shell, daemon, eventloop, tcprelay, udprelay, \
    asyncdns, manager


def main():
    shell.check_python()

    config = shell.get_config(False)

    daemon.daemon_exec(config)

    # 支持多客户端
    if config['port_password']:
        if config['password']:
            logging.warn('warning: port_password should not be used with '
                         'server_port and password. server_port and password '
                         'will be ignored')
    else:
        config['port_password'] = {}
        server_port = config['server_port']
        # 若发现有多用户配置：采用‘端口->密码’的映射方式。
        if type(server_port) == list:
            for a_server_port in server_port:
                config['port_password'][a_server_port] = config['password']
        else:
            config['port_password'][str(server_port)] = config['password']

    if config.get('manager_address', 0):
        logging.info('entering manager mode')
        manager.run(config)
        return

    tcp_servers = []
    udp_servers = []

    if 'dns_server' in config:  # allow override settings in resolv.conf
        dns_resolver = asyncdns.DNSResolver(config['dns_server'],
                                            config['prefer_ipv6'])
    else:
        dns_resolver = asyncdns.DNSResolver(prefer_ipv6=config['prefer_ipv6'])

    # 一个服务器端可以打开多个端口
    # 对于每个端口，都要新建一个对应的处理器
    # 同时从配置文件中删除对应的配置
    port_password = config['port_password']
    del config['port_password']
    for port, password in port_password.items():
        a_config = config.copy()
        a_config['server_port'] = int(port)
        a_config['password'] = password
        logging.info("starting server at %s:%d" %
                     (a_config['server'], int(port)))
        # 逐一加到tcp、udp列表
        tcp_servers.append(tcprelay.TCPRelay(a_config, dns_resolver, False))
        udp_servers.append(udprelay.UDPRelay(a_config, dns_resolver, False))

    def run_server():
        def child_handler(signum, _):
            logging.warn('received SIGQUIT, doing graceful shutting down..')
            # 关闭所有的socket，lambda表达式一句话搞定
            # map(function, sequence[, sequence, ...]) -> list
            # Return a list of the results of applying the function to the items of the argument sequence(s). 
            list(map(lambda s: s.close(next_tick=True),
                     tcp_servers + udp_servers))
        signal.signal(getattr(signal, 'SIGQUIT', signal.SIGTERM),
                      child_handler)

        def int_handler(signum, _):
            sys.exit(1)
        signal.signal(signal.SIGINT, int_handler)

        try:
            loop = eventloop.EventLoop()
            dns_resolver.add_to_loop(loop)
            # 把所有的监听端口添加到事件循环loop中，lambda表达式一句话搞定
            list(map(lambda s: s.add_to_loop(loop), tcp_servers + udp_servers))

            daemon.set_user(config.get('user', None))
            loop.run()
        except Exception as e:
            shell.print_exception(e)
            sys.exit(1)

    # Shadowsocks supports spawning child processes like nginx.
    # You can use --workers to specify how many workers to use.
    # This argument is only supported on Unix and ssserver.
    # Currently UDP relay does not work well on multiple workers.
    # 支持像nginx多进程，可以在config中指定worker的数量。仅在linux下生效。
    # 目前的bug：worker设为大于1时，udp转发有可能工作不正常
    if int(config['workers']) > 1:
        if os.name == 'posix':
            children = []
            is_child = False
            for i in range(0, int(config['workers'])):
                r = os.fork()
                if r == 0:
                    logging.info('worker started')
                    is_child = True
                    run_server()
                    break
                else:
                    children.append(r)
            if not is_child:
                def handler(signum, _):
                    for pid in children:
                        try:
                            os.kill(pid, signum)
                            os.waitpid(pid, 0)
                        except OSError:  # child may already exited
                            pass
                    sys.exit()
                signal.signal(signal.SIGTERM, handler)
                signal.signal(signal.SIGQUIT, handler)
                signal.signal(signal.SIGINT, handler)

                # master
                for a_tcp_server in tcp_servers:
                    a_tcp_server.close()
                for a_udp_server in udp_servers:
                    a_udp_server.close()
                dns_resolver.close()

                for child in children:
                    os.waitpid(child, 0)
        else:
            logging.warn('worker is only available on Unix/Linux')
            run_server()
    else:
        run_server()


if __name__ == '__main__':
    main()
