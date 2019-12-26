#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

""" Worker thread - scans for new bans """

import threading
import lib.database
import netaddr
import asyncio

LOCK = threading.Lock()
DB = None
CLIENTS = None

BADS_HASHED = set()
GOODS_HASHED = set()
ALL_BLOCKS = {}

def init(config, ws):
    global DB, CLIENTS
    DB = lib.database.BlockyDatabase(config)
    CLIENTS = ws
    report()

def report():
    ADDED_BADS, REMOVED_BADS, ADDED_GOODS, REMOVED_GOODS = changes()
    
    if CLIENTS.CLIENTS:
        LOCK.acquire(blocking = True)
        for hid in ADDED_BADS:
            block = ALL_BLOCKS[hid]
            print("Added BAD: %s" % block['hash'])
            asyncio.run(CLIENTS.notify_all("BAD %s" % block['hash']))
        
        for hid in REMOVED_BADS:
            block = ALL_BLOCKS[hid]
            print("Removed BAD: %s" % block['hash'])
            asyncio.run(CLIENTS.notify_all("UNBAD %s" % block['hash']))
        
        for hid in ADDED_GOODS:
            block = ALL_BLOCKS[hid]
            print("Added GOOD: %s" % block['hash'])
            asyncio.run(CLIENTS.notify_all("GOOD %s" % block['hash']))
        
        for hid in REMOVED_GOODS:
            block = ALL_BLOCKS[hid]
            print("Removed GOOD: %s" % block['hash'])
            asyncio.run(CLIENTS.notify_all("UNGOOD %s" % block['hash']))
        
        asyncio.run(CLIENTS.notify_all("COMMIT"))
        LOCK.release()
        
    # Respawn in 15...
    t = threading.Timer(15, report)
    t.start()

async def all(client):
    """ Print all goods/bad IPs to client """
    # Lock and copy
    LOCK.acquire(blocking = True)
    XB =BADS_HASHED.copy()
    XG = GOODS_HASHED.copy()
    LOCK.release()
    
    # Send 'em all
    try:
        for hid in XB:
            await client.send("BAD %s" % hid)
        for hid in XG:
            await client.send("GOOD %s" % hid)
        await client.send("COMMIT")
    except:
        pass # Ignore conn errors
    
    
def changes():
    global BADS_HASHED, GOODS_HASHED
    current_bads = get_banlist(DB)
    current_goods = get_whitelist(DB)
    
    bad_hashes = set()
    good_hashes = set()
    
    # Make hashes for each item
    for item in current_bads:
        hid = "%s %s %s" % (item['ip'], item['epoch'], item['target'])
        item['hash'] = hid
        ALL_BLOCKS[hid] = item
        bad_hashes.update([hid])
    
    for item in current_goods:
        hid = "%s %s %s" % (item['ip'], item['epoch'], item['target'])
        item['hash'] = hid
        ALL_BLOCKS[hid] = item
        good_hashes.update([hid])
    
    LOCK.acquire(blocking = True)
    
    ADDED_BADS = bad_hashes - BADS_HASHED
    REMOVED_BADS = BADS_HASHED - bad_hashes
    
    ADDED_GOODS = good_hashes - GOODS_HASHED
    REMOVED_GOODS = GOODS_HASHED - good_hashes
    
    GOODS_HASHED = good_hashes
    BADS_HASHED = bad_hashes
    
    LOCK.release()
    
    return ADDED_BADS, REMOVED_BADS, ADDED_GOODS, REMOVED_GOODS


def to_block(ipaddress):
    """ Converts an IP address or CIDR block to an IPNetwork object """
    block = None
    if '/' in ipaddress:
        block = netaddr.IPNetwork(ipaddress)
    else:
        if ':' in ipaddress: # IPv6?
            block = netaddr.IPNetwork("%s/128" % ipaddress)
        else: # IPv4?
            block = netaddr.IPNetwork("%s/32" % ipaddress)
    return block

def get_whitelist(DB):
    """ Get the entire whitelist """
    whitelist = []
    res = DB.ES.search(
            index=DB.dbname,
            doc_type="whitelist",
            size = 5000,
            body = {
                'query': {
                    'match_all': {}
                }
            }
        )
    for hit in res['hits']['hits']:
        doc = hit['_source']
        ipaddress = doc.get('ip')
        if ipaddress:
            ipaddress = ipaddress.strip() # blocky/1 bug
            # convert to IPNetwork object
            block = to_block(ipaddress)
            epoch = doc.get('epoch', 0)
            target = doc.get('target', '*')
            if block:
                item = {
                    'ip': block,
                    'epoch': epoch,
                    'target': target,
                }
                whitelist.append(item)
    return whitelist


def get_banlist(DB):
    """ Get the entire banlist """
    banlist = []
    res = DB.ES.search(
            index=DB.dbname,
            doc_type="ban",
            size = 10000,
            body = {
                'query': {
                    'match_all': {}
                }
            }
        )
    for hit in res['hits']['hits']:
        doc = hit['_source']
        ipaddress = doc.get('ip')
        if not ipaddress:
            ipaddress = hit['_id'].replace('_', '/') # Blocky/1 syntax, bah
        if ipaddress:
            ipaddress = ipaddress.strip() # blocky/1 bug
            block = to_block(ipaddress)
            epoch = doc.get('epoch', 0)
            target = doc.get('target', '*')
            if block:
                item = {
                    'ip': block,
                    'epoch': epoch,
                    'target': target,
                }
                banlist.append(item)
    return banlist
