import asyncio
from argparse import ArgumentParser
from asyncio import sleep
from urllib.parse import urlencode

from scapy.layers.l2 import Loopback
from websockets import ClientConnection, ConnectionClosedError, InvalidStatus
from websockets.asyncio.client import connect
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from packet_parser import parse_frame
from generated import packet_pb2

argparse = ArgumentParser()
argparse.add_argument('host', help='Remote host to connect to')
argparse.add_argument('port', type=int, help='Remote port to connect to')
argparse.add_argument('interface', help='Remote network interface to sniff on')
argparse.add_argument('-f', '--filter', help='Optional BPF', default=None)
argparse.add_argument('--pb', '--proto', '--protobuf', action='store_true', help='Enable protobuf communication')

args = argparse.parse_args()

async def recv(ws: ClientConnection):
    while True:
        try:
            ws_message = await ws.recv()
            if args.pb:
                ws_frame = packet_pb2.WsFrame()
                ws_frame.ParseFromString(ws_message)
                pkt = parse_frame(ws_frame.payload)
            else:
                pkt = parse_frame(ws_message)

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
            pkt_bytes = bytes(echo_req)
            if args.pb:
                ws_frame = packet_pb2.WsFrame()
                ws_frame.payload = pkt_bytes
                await ws.send(ws_frame.SerializeToString())
            else:
                await ws.send(pkt_bytes)
            echo_req.seq += 1
            await sleep(1)
        except ConnectionClosedError:
            print("Connection closed, unable to send frame.")
            return
        except Exception as e:
            print(f"Error sending frame: {e}")

if __name__ == '__main__':
    async def main():
        params = {}
        if args.filter:
            params['filter'] = args.filter
        if args.pb:
            params['mode'] = 'protobuf'

        query_params = f'?{urlencode(params)}' if params else ''

        try:
            async with connect(f'ws://{args.host}:{args.port}/connections/{args.interface}{query_params}') as websocket:
                await asyncio.gather(recv(websocket), send(websocket))
        except InvalidStatus as e:
            print(f"Error connecting to websocket: {e.response.body.decode('utf-8')}")
        except Exception as e:
            print(f"Error connecting to websocket: {e}")

    asyncio.run(main())
