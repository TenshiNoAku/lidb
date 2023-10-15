def udp_unpack(data):
    s_port, d_port, length, checksum = struct.unpack('! H H H H', data[:8])
    return s_port, d_port, length, checksum, data[8:]

def IPv4_unpack(ipv4_header):
    vihl, tos, total_len, identification, flags_offset, TTL, proto, header_checksum, s_ip, d_ip = struct.unpack(
        '! B B H H H B B H 4s 4s', ipv4_header)

    x_bit = (flags_offset >> 15) & 1
    DFF = (flags_offset >> 14) & 1
    MFF = (flags_offset >> 13) & 1

    # Extracting Fragment Offset
    frag_offset = flags_offset & 8191

    return vihl, tos, total_len, identification, x_bit, DFF, MFF, frag_offset, TTL, proto, header_checksum, get_ip(
        s_ip), get_ip(d_ip)


def get_ip(ip_bytes):
    return '.'.join(map(str, ip_bytes))

def icmp_unpack(data):
    icmp_type, icmp_code, icmp_checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, icmp_code, icmp_checksum
