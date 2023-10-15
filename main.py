import socket
import struct
from config import *


def unpack_payloads(payload: bin, msgid: int) -> namedtuple:
    return MESSAGECODES[msgid]._make(struct.unpack(MAVLINKFORMATS[msgid], payload))


def mavlink_msg_parce(data: bin) -> dict:
    magic, length, seq, sysid, compid, msgid = data[:6]  # header of mavlink message
    payload = data[6:length + 6]

    return {
        'magic': magic,
        'len': length,
        'seq': seq,
        'sysid': sysid,
        'compid': compid,
        'msgid': msgid,
        'payload': unpack_payloads(payload, msgid)
    }



def getmac(mac_bytes: bytes):
    return ':'.join(map('{:02x}'.format, mac_bytes)).upper()


def ethernet_unpack(eHeader):
    eth_hdr = struct.unpack("!6s6sH", eHeader)
    dest_mac, source_mac, proto = getmac(eth_hdr[0]), getmac(eth_hdr[1]), socket.htons(eth_hdr[2])
    data = {'Destination MAC': dest_mac, 'Source MAC': source_mac, 'PROTO': proto}
    return data



if __name__ == '__main__':

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.connect((IP, PORT))
    sock.sendall(b'1')
    print('connecting...')

    try:
        data, addr = sock.recvfrom(2048)
        while True:
            data, addr = sock.recvfrom(2048)

            eth_header = data[:14]
            print(ethernet_unpack(eth_header))


    except ConnectionResetError as err:
        print('connection refused')

    finally:
        sock.close()
        print('connection closed')
