#!/usr/bin/env python3

import asyncio
import websockets
import ssl
import yaml
import socket

WHOAMI = socket.gethostname()

# Simple socket client registry and functions
CLIENTS = set()

async def add_client(socket):
    """ Add a client to the list of connected ones """
    CLIENTS.add(socket)

async def remove_client(socket):
    """ Remove a client (upon disconnect) from the list of connections """
    CLIENTS.remove(socket)

async def notify_all(msg):
    """ Send a message to all connected clients """
    if CLIENTS:
        await asyncio.wait([client.send(msg) for client in CLIENTS])


async def init_client(socket, path):
    """ Standard entry path for connecting clients.
        Await and parse messages, remove from client list on close """
    await add_client(socket)
    await socket.send("HELLO This is %s. Currently %u clients connected here..." % (WHOAMI, len(CLIENTS)))
    try:
        async for message in socket:
            await notify_all("Got: %s" % message)
            
    finally:
        await remove_client(socket)


def main():
    config = yaml.safe_load(open('./blocky.yaml').read())
    
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(config['security']['chain'], config['security']['key'])
    start_server = websockets.serve(init_client, "0.0.0.0", 3456, ssl = ssl_context)
    asyncio.get_event_loop().run_until_complete(start_server)
    asyncio.get_event_loop().run_forever()


if __name__ == '__main__':
    main()
