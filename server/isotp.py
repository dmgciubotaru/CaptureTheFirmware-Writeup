import struct
import socket

class ISOTP:
    __slots__ = ["conn"]
    __fmt__ = "8B"
    def __init__(self, conn):
        self.conn = conn
        self.conn.settimeout(0.5)
    
    def read(self):
    
        msg = None
        
        while msg == None:
            msg = self._read()
        
        if msg[0]//0x10 > 1:
            return None
        
        if msg[0]//0x10 == 0:
            return msg[1:msg[0]+1]
        
        self._write([0x30] + [0]*7)
        
        size = (msg[0] % 0x10)* 0x100 + msg[1]
        
        data = msg[2:]
        idx = 1
        
        while len(data) < size:
            msg = self._read()
            if not msg or msg[0] != 0x20 + idx:
                return None
            
            idx = (idx + 1) % 0x10
            data = data + msg[1:]
        
        return data
    
    def write(self, data):
        size = len(data)
        
        if size <= 7:
            self._write([0x00 + size] + data)
        else:
            self._write([0x10 + size // 0x100, size % 0x100] + data[:6])
            data = data[6:]
            idx = 0
            
            flow = self._read()
            
            if not flow or flow[0] != 0x30:
                return None
                
            while len(data) > 7:
                idx = (idx + 1) % 0x10
                self._write([0x20 + idx] + data[:7])
                data = data[7:]
            
            self._write([0x20 + idx+1] + data)
               
        
    def _write(self, data):
        data += [0] * (8 - len(data))
        msg = struct.pack(ISOTP.__fmt__, *data)
        self.conn.send(msg)
        
    def _read(self):
        
        try:
            msg = self.conn.recv(8)
            
            if len(msg) != 8:
                return None
            
            return struct.unpack(ISOTP.__fmt__, msg)
            
        except socket.timeout as ex:
            return None
        