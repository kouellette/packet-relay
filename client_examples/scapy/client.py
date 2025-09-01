import asyncio
from argparse import ArgumentParser
from asyncio import sleep

from scapy.layers.l2 import Loopback
from websockets import ClientConnection, ConnectionClosedError, InvalidStatus
from websockets.asyncio.client import connect
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from packet_parser import parse_frame

argparse = ArgumentParser()
argparse.add_argument('host', help='Remote host to connect to')
argparse.add_argument('port', type=int, help='Remote port to connect to')
argparse.add_argument('interface', help='Remote network interface to sniff on')
argparse.add_argument('-f', '--filter', help='Optional BPF', default=None)
args = argparse.parse_args()

async def recv(ws: ClientConnection):
    while True:
        try:
            pkt_bytes = await ws.recv()
            pkt = parse_frame(pkt_bytes)
            print(pkt.show())
        except ConnectionClosedError:
            print("Connection closed, breaking loop.")
            break
        except Exception as e:
            print(f"Error parsing frame: {e}")
            
async def send(ws: ClientConnection):
    # MacOS loopback ICMPv6 echo request.
    # May need to change type value based on BSD flavor or switch to CookedLinux.
    echo_req = Loopback(type = 30) / IPv6(dst="::1") / ICMPv6EchoRequest()

    while True:
        # Send echo request every second.
        try:
            await ws.send(bytes(echo_req))
            echo_req.seq += 1
            await sleep(1)
        except ConnectionClosedError:
            print("Connection closed, unable to send frame.")
            return
        except Exception as e:
            print(f"Error sending frame: {e}")

if __name__ == '__main__':
    async def main():
        filter_param = f'?filter={args.filter}' if args.filter else ''
        try:
            async with connect(f'ws://{args.host}:{args.port}/connections/{args.interface}{filter_param}') as websocket:
                await asyncio.gather(recv(websocket), send(websocket))
        except InvalidStatus as e:
            print(f"Error connecting to websocket: {e.response.body.decode('utf-8')}")
        except Exception as e:
            print(f"Error connecting to websocket: {e}")

    asyncio.run(main())
