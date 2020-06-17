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

import asyncio
import websockets
import socket
import time

# Simple socket client registry and functions
CLIENTS = set()
WHOAMI = socket.getfqdn()
IPS = {}
LW = None

async def add_client(socket):
    """ Add a client to the list of connected ones """
    print("CONNECT:    %s [:%s]" % (socket.remote_address[0], socket.remote_address[1]))
    IPS[socket] = socket.remote_address[0]
    CLIENTS.add(socket)

async def remove_client(socket):
    """ Remove a client (upon disconnect) from the list of connections """
    print("DISCONNECT: %s" % IPS[socket])
    CLIENTS.remove(socket)

async def notify_all(msg):
    """ Send a message to all connected clients """
    if CLIENTS:
        try:
            await asyncio.wait([client.send(msg) for client in CLIENTS])
        except:
            pass # Ignore for now..

async def init_client(socket, path):
    """ Standard entry path for connecting clients.
        Await and parse messages, remove from client list on close """
    await add_client(socket)
    await socket.send("HELLO This is %s. Currently %u clients connected here..." % (WHOAMI, len(CLIENTS)))
    try:
        async for message in socket:
            if message == 'ALL': # Get all blocks
                await LW.all(socket)
            if message.startswith('ALL '): # Get all blocks since...
                cmd, epoch = message.split(' ', 1)
                await LW.all(socket, int(epoch))
    except:
        pass
    finally:
        await remove_client(socket)

def serve(config, ssl_context, worker):
    global LW
    LW = worker
    bind = '::'
    port = 3456
    if 'server' in config:
        bind = config['server'].get('bind', '::')
        port = config['server'].get('port', 3456)
    start_server = websockets.serve(init_client, bind, port, ping_interval = 60, ping_timeout = 180, ssl = ssl_context)
    asyncio.get_event_loop().run_until_complete(start_server)
    asyncio.get_event_loop().run_forever()
    
