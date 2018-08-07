#!/usr/bin/python
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
守护进程
'''

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import sys
import logging
import signal
import time
from shadowsocks import common, shell

# this module is ported from ShadowVPN daemon.c


def daemon_exec(config):
    if 'daemon' in config:
        if os.name != 'posix':
            raise Exception('daemon mode is only supported on Unix')
        command = config['daemon']
        if not command:
            command = 'start'
        pid_file = config['pid-file']
        log_file = config['log-file']
        if command == 'start':
            daemon_start(pid_file, log_file)
        elif command == 'stop':
            daemon_stop(pid_file)
            # always exit after daemon_stop
            sys.exit(0)
        elif command == 'restart':
            daemon_stop(pid_file)
            daemon_start(pid_file, log_file)
        else:
            raise Exception('unsupported daemon command %s' % command)


def write_pid_file(pid_file, pid):
    import fcntl
    import stat

    try:
        # 读写、创建、文件所有者具可执行权限、可写入权限。
        fd = os.open(pid_file, os.O_RDWR | os.O_CREAT,
                     stat.S_IRUSR | stat.S_IWUSR)
    except OSError as e:
        shell.print_exception(e)
        return -1
    # 获得当前fd的标记
    flags = fcntl.fcntl(fd, fcntl.F_GETFD)
    assert flags != -1
    # close on exec, not on-fork, 意为如果对描述符设置了FD_CLOEXEC，使用exec执
    # 行的程序里，此描述符被关闭，不能再使用它，但是在使用fork调用的子进程中，此描述符并不关闭，仍可使用。
    flags |= fcntl.FD_CLOEXEC
    # 设置标志
    r = fcntl.fcntl(fd, fcntl.F_SETFD, flags)
    assert r != -1
    # There is no platform independent way to implement fcntl(fd, F_SETLK, &fl)
    # via fcntl.fcntl. So use lockf instead
    try:
        # 上锁：排他锁，非阻塞。
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, 0, 0, os.SEEK_SET)
    except IOError:
        r = os.read(fd, 32)
        if r:
            logging.error('already started at pid %s' % common.to_str(r))
        else:
            logging.error('already started')
        os.close(fd)
        return -1
    # 截断文件到长度0
    os.ftruncate(fd, 0)
    # 写入pid数值到文件
    os.write(fd, common.to_bytes(str(pid)))
    return 0

# C++的freopen()函数：
# 通常在设计好算法和程序后，要在调试环境（例如VC等）中运行程序，输入测试数据，当能得到正确运行结果后，才将程序提交到oj中。
# 但由于调试往往不能一次成功，每次运行时，都要重新输入一遍测试数据，对于有大量输入数据的题目，输入数据需要花费大量时间。
# 使用freopen函数可以解决测试数据输入问题，避免重复输入，不失为一种简单而有效的解决方法。

# 形参stream: 一个文件，通常使用标准流文件。
# freopen("a.txt","r",stdin); //读取a.txt中的内容，并重定向至stdiin
# freopen("b.txt","w",stdout); //将stdout中内重定向至b.txt
# 说白了就是关闭已经打开的stream，然后将stream跟f相连。
def freopen(f, mode, stream):
    oldf = open(f, mode)
    oldfd = oldf.fileno()
    newfd = stream.fileno()
    os.close(newfd)
    os.dup2(oldfd, newfd)

# 为避免挂起控制终端将Daemon放入后台执行，
# 方法是在进程中调用fork使父进程终止，让Daemon在子进程中后台执行。
# 参考 http://baike.baidu.com/view/53123.htm
def daemon_start(pid_file, log_file):

    def handle_exit(signum, _):
        # SIGTERM：程序结束(terminate)信号, 与SIGKILL不同的是该信号可以被阻塞和处理。
        # 关于信号：linux 信号量之SIGNAL 谷歌一下
        if signum == signal.SIGTERM:
            sys.exit(0)
        sys.exit(1)

    # 出现以下信号为终止信号，执行退出。
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    # fork only once because we are sure parent will exit
    pid = os.fork()
    assert pid != -1

    # 父进程为pid=0
    # 子进程pid>0
    # 若下面if的条件为True，证明执行者是父进程，进入if语句执行：等待5秒并自杀
    if pid > 0:
        # parent waits for its child
        # 父进程会等待5秒，用于接收子进程的终结信号
        time.sleep(5)
        sys.exit(0)

    # child signals its parent to exit
    # 以下代码是子进程执行，因为父亲在等待5秒。最后发出信号杀死父进程
    ppid = os.getppid()
    pid = os.getpid()
    if write_pid_file(pid_file, pid) != 0:
        os.kill(ppid, signal.SIGINT)
        sys.exit(1)
        
    # setsid创建一个新的会话，并担任该会话组的组长。作用：
    # 1 让进程摆脱原会话的控制
    # 2 让进程摆脱原进程组的控制
    # 3 让进程摆脱原控制终端的控制
    os.setsid()
    
    # SIG_IGN specifies that the signal should be ignored.忽略挂起信号
    signal.signal(signal.SIGHUP, signal.SIG_IGN)

    print('started')
    # 这么残忍，再杀一次父进程！
    os.kill(ppid, signal.SIGTERM)

    sys.stdin.close()
    try:
        # 追加方式打开log文件，将信息重定向为该文件
        freopen(log_file, 'a', sys.stdout)
        freopen(log_file, 'a', sys.stderr)
    except IOError as e:
        shell.print_exception(e)
        sys.exit(1)


def daemon_stop(pid_file):
    import errno
    try:
        with open(pid_file) as f:
            # 读出pid数值
            buf = f.read()
            pid = common.to_str(buf)
            if not buf:
                logging.error('not running')
    except IOError as e:
        shell.print_exception(e)
        if e.errno == errno.ENOENT:
            # always exit 0 if we are sure daemon is not running
            logging.error('not running')
            return
        sys.exit(1)
    pid = int(pid)
    if pid > 0:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError as e:
            if e.errno == errno.ESRCH:
                logging.error('not running')
                # always exit 0 if we are sure daemon is not running
                return
            shell.print_exception(e)
            sys.exit(1)
    else:
        logging.error('pid is not positive: %d', pid)

    # sleep for maximum 10s
    for i in range(0, 200):
        try:
            # query for the pid
            os.kill(pid, 0)
        except OSError as e:
            if e.errno == errno.ESRCH:
                break
        time.sleep(0.05)
    else:
        logging.error('timed out when stopping pid %d', pid)
        sys.exit(1)
    print('stopped')
    os.unlink(pid_file)


def set_user(username):
    if username is None:
        return

    import pwd
    import grp

    try:
        pwrec = pwd.getpwnam(username)
    except KeyError:
        logging.error('user not found: %s' % username)
        raise
    user = pwrec[0]
    uid = pwrec[2]
    gid = pwrec[3]

    cur_uid = os.getuid()
    if uid == cur_uid:
        return
    if cur_uid != 0:
        logging.error('can not set user as nonroot user')
        # will raise later

    # inspired by supervisor
    if hasattr(os, 'setgroups'):
        groups = [grprec[2] for grprec in grp.getgrall() if user in grprec[3]]
        groups.insert(0, gid)
        os.setgroups(groups)
    os.setgid(gid)
    os.setuid(uid)
