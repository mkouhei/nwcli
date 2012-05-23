#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Copyright (C) 2012 Kouhei Maeda <mkouhei@palmtb.net>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
import getpass
import sys
import telnetlib
import argparse
from __init__ import __version__

default_cmd = 'terminal length 0\n'
default_timeout = 1


def getPassword(args, enable=False):
    from getpass import getpass
    password = ''
    if args.__dict__.get('password'):
        password = args.password
    elif args.__dict__.get('P'):
        while True:
            if password:
                break
            else:
                password = getpass(prompt='login password: ')

    if enable:
        enpass = ''
        if args.__dict__.get('enpass'):
            enpass = args.enpass
        elif args.__dict__.get('E'):
            while True:
                if enpass:
                    break
                else:
                    enpass = getpass(prompt='enable password: ')
        return password, enpass
    else:
        return password


def login(server, password, username=False, enpass=False):
    from sys import stderr as err
    import socket

    try:
        tn = telnetlib.Telnet(server, timeout=default_timeout)

        if password:
            tn.read_until('Password:')
            tn.write(password + '\n')
        if enpass:
            tn.write('enable\n')
            tn.read_until('Password:')
            tn.write(enpass + '\n')
        tn.write(default_cmd)
        return tn
    except socket.timeout as e:
        err.write("ERROR: %s\n" % e)
        exit(1)


def execCommand(session, cmd):
    session.write(cmd)
    session.write('exit\n')
    stream = session.read_all()
    return(stream)


def backup(args):
    cmd = 'show running-config\n'
    enable = True
    password, enpass = getPassword(args, enable)
    session = login(args.server, password, args.username, enpass)
    stream = execCommand(session, cmd)
    saveConfig(args.server, stream)


def showint(args):
    cmd = 'show interface status\n'
    password = getPassword(args)
    session = login(args.server, password, args.username)
    stream = execCommand(session, cmd)
    dictFormat(stream, 'int')


def showmac(args):
    cmd = 'show mac address-table dynamic\n'
    password = getPassword(args)
    session = login(args.server, password, args.username)
    stream = execCommand(session, cmd)
    dictFormat(stream, 'mac')


def checkConfig(filename):
    import os.path
    import sys
    if sys.version_info > (2, 6) and sys.version_info < (2, 8):
        import ConfigParser as configparser
    elif sys.version_info > (3, 0):
        import configparser as configparser
    conf = configparser.SafeConfigParser(allow_no_value=False)
    conf.read(filename)

    try:
        server = conf.get('global', 'server')
    except configparser.NoOptionError:
        server = False

    try:
        username = conf.get('auth', 'username')
    except configparser.NoOptionError:
        username = False

    try:
        password = conf.get('auth', 'password')
    except configparser.NoOptionError:
        password = False

    try:
        enpass = conf.get('auth', 'enpass')
    except configparser.NoOptionError:
        enpass = False

    return server, password, enpass, username


def setoption(obj, keyword, prefix=False, required=False):

    if keyword == 'server':
        obj.add_argument(
            '-r', dest='server', required=True,
            help='specify switch hostname or IP address')

    if keyword == 'username':
        obj.add_argument('-u', dest='username',
                         help='switch username')

    if keyword == 'password':
        group = obj.add_mutually_exclusive_group(required=True)
        group.add_argument('-p', dest='password',
                           help='switch password')
        group.add_argument('-P', action='store_true',
                           help='switch password prompt')

    if keyword == 'enpass':
        group = obj.add_mutually_exclusive_group(required=True)
        group.add_argument('-e', dest='enpass',
                           help='switch enable password')
        group.add_argument('-E', action='store_true',
                           help='switch enable password prompt')


def conn_options(obj, server=False, enable=False, password=False,
                 enpass=False, username=False):

    if enable:
        if server and username and password and enpass:
            obj.set_defaults(server=server, username=username,
                             password=password, enpass=enpass)

        elif server and password and enpass:
            obj.set_defaults(server=server, password=password,
                             enpass=enpass)
    else:
        if server and password:
            obj.set_defaults(server=server, password=password)

    # when not setting [global].server in ${HOME}/.nwclirc
    if not server:
        setoption(obj, 'server')

    # when not setting [auth].username in ${HOME}/.nwclirc
    if not username:
        setoption(obj, 'username')

    # when not setting [auth].password in ${HOME}/.nwclirc
    if not password:
        setoption(obj, 'password')

    # when not setting [auth].enpass in ${HOME}/.nwclirc
    if enable and not enpass:
        setoption(obj, 'enpass')


def parse_options():
    import os

    server, username, password, enpass = False, False, False, False

    prs = argparse.ArgumentParser(description='usage')
    prs.add_argument('-v', '--version', action='version',
                     version=__version__)

    if os.environ.get('HOME'):
        CONFIGFILE = os.environ.get('HOME') + '/.nwclirc'
        if os.path.isfile(CONFIGFILE):
            server, password, enpass, username \
                = checkConfig(CONFIGFILE)

    subprs = prs.add_subparsers(help='commands')

    # Backup running configuration
    sub_backup = subprs.add_parser('backup',
                                   help='backup running-configuration')
    conn_options(sub_backup, server, True, password, enpass, username)
    sub_backup.set_defaults(func=backup)

    sub_show = subprs.add_parser('show',
                                 help='Show <show subcommand>')
    subshow_prs = sub_show.add_subparsers(help='show subcommands')

    # Show interface status
    subshow_int = subshow_prs.add_parser(
        'int', help='show interface status')
    conn_options(subshow_int, server, False, password, username=username)
    subshow_int.set_defaults(func=showint)

    # Show mac address-table dynamic
    subshow_mac = subshow_prs.add_parser(
        'mac', help='show mac address-table dynamic')
    conn_options(subshow_mac, server, False, password, username=username)
    subshow_mac.set_defaults(func=showmac)

    args = prs.parse_args()
    return args


def saveConfig(server, stream):
    import datetime as d
    filename = server + '_' + \
        d.date.strftime(d.datetime.now(), '%Y%m%d-%H%M%S')
    f = open(filename, 'w')
    f.write(stream)
    f.close()


def dictFormat(stream, type):
    for line in stream.splitlines():
        import re
        if type == 'int':
            line_d = re.split('\s*', line)
            if re.match('^Gi', line_d[0]):
                print(line_d)
        elif type == 'mac':
            if line.find('DYNAMIC') >= 0:
                line_d = re.split('\s*', re.split('^\s*', line)[1])
                print(line_d)


def main():
    import sys

    try:
        args = parse_options()
        args.func(args)
    except RuntimeError as e:
        sys.stderr.write("ERROR: %s\n" % e)
        return

if __name__ == '__main__':
    main()
