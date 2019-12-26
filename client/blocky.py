#!/usr/bin/env python3

import asyncio
import websockets
import ssl
import yaml


async def hello(config):
    uri = config['server']['hostname']
    async with websockets.connect(uri) as websocket:
        greeting = await websocket.recv()
        print(greeting)
        
        name = input("What's your name? ")

        await websocket.send(name)
        print(f"> {name}")

        greeting = await websocket.recv()
        print(f"< {greeting}")


def main():
    config = yaml.safe_load(open('./blocky.yaml').read())
    asyncio.get_event_loop().run_until_complete(hello(config))
    print("DONE")

if __name__ == '__main__':
    main()
