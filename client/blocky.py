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

import os
import subprocess
import re
import json
import requests
import netaddr
import socket
import time
import sys
import syslog
import copy
import asyncio
import websockets
import ssl
import yaml
import threading
import copy

DEBUG = False
CONFIG = None
SYSLOG = None
MAX_IPTABLES_TRIES = 10
IPTABLES_EXEC = '/sbin/iptables'
IP6TABLES_EXEC = '/sbin/ip6tables'
LAST_UPLOAD = 0
UPLOAD_FREQUENCY = 180

BANLIST = []
WHITELIST = []

LOCK = threading.Lock()



def upload_iptables():
    global BANLIST
    # First, get our rules and post 'em to the server
    ychains = CONFIG.get('iptables', {}).get('chains')
    chains = ychains or ['INPUT']
    LOCK.acquire(blocking = True)
    BANLIST = []
    for chain in chains:
       BANLIST += getbans(chain)
    mylistbare = copy.deepcopy(BANLIST)
    LOCK.release()
    try:
        for el in mylistbare:
           del el['asNet']
        js = {
           'hostname': CONFIG['client']['hostname'],
           'iptables': mylistbare
        }
        apiurl = "%s/myrules" % CONFIG['server']['apiurl']
        rv = requests.put(apiurl, json = js)
        print(rv.status_code)
        assert(rv.status_code == 200)
        LAST_UPLOAD = time.time()
    except Exception as e:
        syslog.syslog(syslog.LOG_WARNING, "Could not send my iptables list to server at %s - server down?" % apiurl)
        print(e)
        print(rv.text)
        
    
    # Respawn upload process later...
    t = threading.Timer(CONFIG['client'].get('uploadinterval', 180), upload_iptables)
    t.start()

async def process_changes(whitelist, banlist, websocket):
    global BANLIST
    LOCK.acquire(blocking = True)
    XBANLIST = copy.deepcopy(BANLIST)
    LOCK.release()
    ychains = CONFIG.get('iptables', {}).get('chains')
    chains = ychains if ychains else ['INPUT']
    whiteblocks = []
    if not (whitelist or banlist):
        return
    syslog.syslog(syslog.LOG_INFO, "Processing Blocky change-set (%u entries)" % (len(whitelist) + len(banlist)))
    processed = 0
    for ip in whitelist:
         if ip:
            block = None
            if '/' in ip:
               block = netaddr.IPNetwork(ip)
            else:
               if ':' in ip:
                  block = netaddr.IPNetwork("%s/128" % ip) # IPv6
               else:
                  block = netaddr.IPNetwork("%s/32" % ip)  # IPv4
            whiteblocks.append(block)
            found = inlist(XBANLIST, ip)
            while found:
               entry = found[0]
               syslog.syslog(syslog.LOG_INFO, "Removing %s from block list (found at line %s as %s)" % (ip, entry['linenumber'], entry['source']))
               if not unban_line(ip, entry['linenumber'], chain = entry.get('chain', 'INPUT')):
                  syslog.syslog(syslog.LOG_WARNING, "Could not remove ban for %s from iptables!" % ip)
               else:
                # If unbanned someone, refresh banlist
                LOCK.acquire(blocking = True)
                XBANLIST = []
                for chain in chains:
                  XBANLIST += getbans(chain)
                LOCK.release()
                found = inlist(XBANLIST, ip)
    
    # Then process bans
    for ip in banlist:
      if ip:
            processed += 1
            if (processed % 500) == 0:
               syslog.syslog(syslog.LOG_INFO, "Processed %u entries..." % processed)
            banit = True
            block = None
            if '/' in ip:
               block = netaddr.IPNetwork(ip)
               # We never ban larger than a /8 on ipv4 and /56 on ipv6
               if (block.version == 4 and block.size > (2**24)) or (block.version == 6 and block.size > (2^72)):
                  syslog.syslog(syslog.LOG_WARNING, "%s was requested banned but the net block is too large (%u IPs)" % (block, block.size))
                  continue
            else:
               if ':' in ip:
                  block = netaddr.IPNetwork("%s/128" % ip) # IPv6
               else:
                  block = netaddr.IPNetwork("%s/32" % ip)  # IPv4
            for wblock in whiteblocks:
               if block in wblock or wblock in block:
                  syslog.syslog(syslog.LOG_WARNING, "%s was requested banned but %s is whitelisted, ignoring ban" % (block, wblock))
                  banit = False
            if banit:
               found = inlist(XBANLIST, ip, False)
               if not found:
                  syslog.syslog(syslog.LOG_INFO, "Adding %s to block list" % ip)
                  if not ban(ip):
                     syslog.syslog(syslog.LOG_WARNING, "Could not add ban for %s in iptables!" % ip)
    LOCK.acquire(blocking = True)
    BANLIST = []
    for chain in chains:
      BANLIST += getbans(chain)
    LOCK.release()
   # All done for this time!

def getbans(chain = 'INPUT'):
   """ Gets a list of all bans in a chain """
   banlist = []
   
   # Get IPv4 list
   for i in range(0,MAX_IPTABLES_TRIES):
      out = None
      try:
         out = subprocess.check_output([IPTABLES_EXEC, '--list', chain, '-n', '--line-numbers'], stderr = subprocess.STDOUT)
      except subprocess.CalledProcessError as err:
         if 'you must be root' in str(err.output):
            print("Looks like blocky doesn't have permission to access iptables, giving up completely! (are you running as root?)")
            sys.exit(-1)
         if 'No chain/target/match' in str(err.output):
            continue
         time.sleep(1) # write lock, probably
      if out:
         for line in out.decode('ascii').split("\n"):
            m = re.match(r"^(\d+)\s+([A-Z]+)\s+(all|tcp|udp)\s+(\S+)\s+([0-9a-f.:/]+)\s+([0-9a-f.:/]+)\s*(.*?)$", line)
            if m:
               ln = m.group(1)
               action = m.group(2)
               protocol = m.group(3)
               option = m.group(4)
               source = m.group(5)
               destination = m.group(6)
               extensions = m.group(7)
               
               entry = {
                  'chain': chain,
                  'linenumber': ln,
                  'action': action,
                  'protocol': protocol,
                  'option': option,
                  'source': source,
                  'asNet': netaddr.IPNetwork(source),
                  'destination': destination,
                  'extensions': extensions,
               }
               
               banlist.append(entry)
         break
   # Get IPv6 list
   if not os.path.exists(IP6TABLES_EXEC):
      return banlist
   for i in range(0,MAX_IPTABLES_TRIES):
      try:
         out = subprocess.check_output([IP6TABLES_EXEC, '--list', chain, '-n', '--line-numbers'], stderr = subprocess.STDOUT)
      except subprocess.CalledProcessError as err:
         if 'you must be root' in str(err.output):
            print("Looks like blocky doesn't have permission to access iptables, giving up completely! (are you running as root?)")
            sys.exit(-1)
         if 'No chain/target/match' in str(err.output):
            continue
         time.sleep(1) # write lock, probably
      if out:
         for line in out.decode('ascii').split("\n"):
            # Unlike ipv4 iptables, the 'option' thing is blank here, so omit it
            m = re.match(r"^(\d+)\s+([A-Z]+)\s+(all|tcp|udp)\s+([0-9a-f.:/]+)\s+([0-9a-f.:/]+)\s*(.*?)$", line)
            if m:
               ln = m.group(1)
               action = m.group(2)
               protocol = m.group(3)
               source = m.group(4)
               destination = m.group(5)
               extensions = m.group(6)
               
               entry = {
                  'chain': chain,
                  'linenumber': ln,
                  'action': action,
                  'protocol': protocol,
                  'option': '---',
                  'source': source,
                  'asNet': netaddr.IPNetwork(source),
                  'destination': destination,
                  'extensions': extensions,
               }
               
               banlist.append(entry)
         break
   return banlist
      
def iptables(ip, action):
    """ Runs an iptables action on an IP (-A, -C or -D), returns true if
        succeeded, false otherwise """
    try:
        exe = IPTABLES_EXEC
        if ':' in ip:
            exe = IP6TABLES_EXEC
        subprocess.check_call([
            exe,
            action, "INPUT",
            "-s", ip,
            "-j", "DROP",
            "-m", "comment",
            "--comment",
            "Banned by Blocky/3.0"
        ], stderr=open(os.devnull, 'wb'))
    except subprocess.CalledProcessError as err: # iptables error, expected result variant
        print(err.output)
        return False
    except OSError as err:
        print("%s not found or inaccessible: %s" % (exe, err))
        return False
    return True
   

def ban(ip):
   """ Bans an IP or CIDR block generically """
   if iptables(ip, '-A'):
      return True
   return False

def unban_line(ip, linenumber, chain = 'INPUT'):
    """ Unbans an IP or block by line number """
    if not linenumber:
      return
    exe = IPTABLES_EXEC
    if ':' in ip:
      exe = IP6TABLES_EXEC
    if DEBUG:
      print("Would have removed line %s from %s chain in iptables here..." % (linenumber, chain))
      return True
    try:
        subprocess.check_call([
            exe,
            '-D', chain, linenumber
        ], stderr=open(os.devnull, 'wb'))
    except subprocess.CalledProcessError as err: # iptables error, expected result variant
        return False
    except OSError as err:
        print("%s not found or inaccessible: %s" % (exe, err))
        return False
    return True

def inlist(banlist, ip, canContain = True):
   """ Check if an IP or CIDR is listed in iptables,
   either by itself or contained within a block (or the reverse) """
   lines = []
   if '/0' in ip: # DO NOT WANT
      return lines
   # First, check verbatim
   for entry in banlist:
      if entry['source'] == ip:
         lines.append(entry)
   # Check if block, then check for matches within
   if '/' in ip:
      me = netaddr.IPNetwork(ip)
      for entry in banlist:
         them = entry['asNet']
         if them in me:
            if canContain or (len(them) >= len(me)):
                lines.append(entry)
   
   # Then the reverse; IP found within blocks?
   else:
      me = netaddr.IPAddress(ip)
      for entry in banlist:
         if '/' in entry['source'] and '/0' not in entry['source']: # blocks, but not /0
            them = entry['asNet']
            if me in them:
               lines.append(entry)
   return lines


async def hello(epoch):
    uri = CONFIG['server']['wshost']
    while True:
        async with websockets.connect(uri) as websocket:
            greeting = await websocket.recv()
            syslog.syslog(syslog.LOG_INFO, "[%s] %s" % (time.time(), greeting))
            
            banlist = []
            whitelist = []
    
            await websocket.send('ALL %s' % epoch)
            while True:
                try:
                    response = await websocket.recv()
                except Exception as e:
                    syslog.syslog(syslog.LOG_WARNING, str(e))
                    break # Lost connection?
                if response:
                    if response == 'COMMIT':
                        await websocket.send("OKAY")
                        try:
                            await process_changes(whitelist, banlist, websocket)
                            epoch = int(time.time())
                        except Exception as e:
                            syslog.syslog("[%s] Could not process blocky changelist: %s" % (time.time(), e))
                        whitelist = []
                        banlist = []
                    else:
                        cmd, ip, epoch, target = response.split(' ', 3)
                        if cmd == 'BAD':
                            if target == CONFIG['client']['hostname'] or target == '*':
                                banlist.append(ip)
                        elif cmd == 'GOOD':
                            if target == CONFIG['client']['hostname'] or target == '*':
                                whitelist.append(ip)
        syslog.syslog(syslog.LOG_WARNING, "[%u] Server disconnected, reconnecting in 30 seconds" % time.time())
        time.sleep(30)

def psyslog(a,b):
   """ nasty hack for copying syslog calls to stdout """
   SYSLOG(a, b)
   print("- " + b)

def main():
    global CONFIG
    # Figure out who we are
    me = socket.getfqdn()
    
    # Try opening the epoch file
    epoch = 0
    try:
        epoch = int(open("epoch.dat").read())
    except:
        pass
    # Set new epoch
    with open("epoch.dat", "w") as f:
        f.write("%u" % time.time())
        f.close()
    
    # Load YAML
    CONFIG = yaml.load(open('./blocky.yaml').read())
    if 'client' not in CONFIG:
       CONFIG['client'] = {}
    if 'hostname' not in CONFIG['client']:
       CONFIG['client']['hostname'] = me
    
    # Get current list of bans in iptables, upload it to blocky server
    upload_iptables()
     
    # Start async loop
    asyncio.get_event_loop().run_until_complete(hello(epoch))
    print("EXITING")

if len(sys.argv) == 2 and sys.argv[1] == 'test':
    SYSLOG = syslog.syslog
    syslog.syslog = psyslog

if __name__ == '__main__':
    main()
