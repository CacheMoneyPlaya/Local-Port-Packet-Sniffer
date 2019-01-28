import socket
import struct
import textwrap


def main():
    #socket(1,2,3): 1 = Socket Family, 2 = Socket Type, 3 = Protocol, usually left out
    #socket.AF_INET is for more observing, socket.AF_PACKET is more for manipulating packets
    #socket.SOCKET_RAW provides access to the underlying protocols, which support socket abstractions, and are needed for packet sniffing
    #socket.ntohs() makes sure bite order is correct and is usable accross all machines..I think?
    conn = socket.socket(socket.AF_PACKET, socket.SOCKET_RAW, socket.ntohs(3))

    while TRUE:
     raw_data, address = conn.recvfrom(65536)
     dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
     print('\nEthernet frame:')
     print('destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))



#Unpack ethernet frame: data = 1's & 0's. each section of data passed is 14 bytes, [6,6,2], [dest,src,type]
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(dest_mac), get_mac_address(src_mac), socket.htons(proto), data[14:]

#Return properly formatted mac address: i.e.(AA:BB:CC:DD:EE:FF)
def get_mac_address(byte_address):
    bytes_str = map('{:02x}'.format(), byte_address)
    return ':'.join(bytes_str).upper()

main()
