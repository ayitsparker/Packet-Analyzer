import socket
import struct
import textwrap

def main():
	HOST = socket.gethostbyname(socket.gethostname())

	# create a raw socket and bind it to the public interface
	conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
	conn.bind((HOST, 0))

	# Include IP headers
	conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

	# receive all packages
	conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
	while True:
		rawData, addr = conn.recvfrom(65565)
		destMac, srcMac, ethProto, data = ethernet_frame(rawData)
		print('\nCurrent Frame: ')
		print('Destination: {}, Source: {}, Protocol: {}'.format(destMac, srcMac, ethProto))
		if ethProto == 8:
			version, headLen, ttl, proto, src, target, data = getIPHeader(data)
			print(proto)
			if proto == 1:
				print('Packet Type: ICMP')
				print('\t    Data:{}'.format(getICMP(data)[3]))
			elif proto == 6:
				print('Packet Type: TCP')
				print('\t    Data:{}'.format(getTCP(data)[3]))

def getIPHeader(data):
	vHeadLen=data[0]
	version=vHeadLen>>4
	headLen=(vHeadLen&15)*4
	ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
	return version, headLen, ttl, proto, addrString(src), addrString(target), data[headLen:]

def addrString(addr):
	return '.'.join(map(str, addr))

def ethernet_frame(data):
	print(data[:14])
	destMac, srcMac, proto = struct.unpack('! 6s 6s H', data[:14])
	return getMac(destMac), getMac(srcMac), socket.htons(proto), data[14:]

def getMac(bytesAdd):
	bytesStr = map('{:02x}'.format, bytesAdd)
	return ':'.join(bytesStr).upper()

def getICMP(data):
	icmpType, code, crc = struct.unpack('! B B H', data[:4])
	return icmpType, code, crc, data[4:]

def getTCP(data):
	srcPort, destPort, sequence, ack, offsetFlags=struct.unpack('H H L L H', data[:14])
	offset=(offsetFlags>>12)*4
	urgFlag=(offsetFlags&32)>>5
	ackFlag=(offsetFlags&16)>>4
	pshFlag=(offsetFlags&8)>>3
	rstFlag=(offsetFlags&4)>>2
	synFlag=(offsetFlags&2)>>1
	finFlag=(offsetFlags&1)
	return srcPort, destPort, sequence, ack, offsetFlags, urgFlag, ackFlag, pshFlag, rstFlag, synFlag, finFlag, data[offset:]

def multiLineFormat(prefix, string, size=80):
	size-=len(prefix)
	if isinstance(string, bytes):
		string =''.join(r'\x{:02x}'.format(byte) for byte in string)
		if size % 2:
			size-=1
	return '\n'.join([prefix +line for line in textwrap.wrap(string, size)])

main()