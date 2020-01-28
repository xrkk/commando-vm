# -*- coding: utf-8 -*-
# !/usr/bin/python3

"""
检查 package 的缺失
"""


import os
import csv
import json


def package_diff():
    """."""
    csv_flare = r'C:\Users\Admin\Downloads\flare-vm-master\packages.csv'
    csv_commando = r'C:\Users\Admin\Downloads\commando-vm-master\packages.csv'

    flare_list = []
    with open(csv_flare, encoding='utf-8') as f_flare:
        csv_reader = csv.reader(f_flare, delimiter=',')
        for i, row in enumerate(csv_reader):
            if row:
                flare_list.append(row[0].strip())
                # print(f'flare: {row[0]}')

    commando_list = []
    with open(csv_commando, encoding='utf-8') as f_commando:
        csv_reader = csv.reader(f_commando, delimiter=',')
        for i, row in enumerate(csv_reader):
            if row:
                commando_list.append(row[0].strip())
                # print(f'commando: {row[0]}')

    print(f'flare: {len(flare_list)}')
    print(f'commando: {len(commando_list)}')

    diff = set(flare_list).difference(commando_list)
    print(f'diff: {len(diff)}')
    for d in diff:
        print(f'diff: {d}')


def update_package(remove_list=None, add_list=None):
    """."""
    profile_json = r'profile_old.json'
    with open(profile_json, mode='r') as f:
        
        content = f.read()
        # print(content)
        content = content.replace("\'", "\\")
        # print(content)
        j = json.loads(content)
        # print(type(j))
        print(j)

        if not remove_list and not add_list:
            return

        if remove_list:
            [j.pop(x) for x in remove_list if x in j]

        if add_list:
            pass

        with open('profile.json', mode='w+') as f_new:
            content_new = json.dumps(j, indent=4)
            # 不一定正确???
            content_new = content_new.replace(r"\\/", r"\'/").replace(r'\\"', "\\'\"")
            f_new.write(content_new)

if __name__ == '__main__':

    # package_diff()

    remove_list = [
        'pidgin.fireeye',
        'farmanager.flare',
        'gimp.fireeye',
        'Greenshot.fireeye',
        'hexchat.fireeye',
        'keepass.fireeye',
        'thunderbird.fireeye',
        'vlc.fireeye',
        'yed.fireeye',
        'citrix-receiver.fireeye',
        'kali.fireeye',
        'openvpn.fireeye',
        'telnet.fireeye',
        'vim.flare',
        'winscp.fireeye',
        'vmware-horizon-client.fireeye',
        'vmwarevsphereclient.fireeye',
        'putty.fireeye',
        'vnc-viewer.fireeye',
        'neo4j-community.fireeye',
        'sqlitebrowser.fireeye',
    ]
    add_list = [

    ]
    update_package(remove_list=remove_list, add_list=add_list)
    
