import isotp
import diag
from functools import reduce

class Diag:
    __slots__ = ["tp","session","lock","services", "fw","mutex","address"]
    

    nrc = {
                    0x11: "serviceNotSupported",
                    0x12: "subFunctionNotSupported",
                    0x13: "incorrectMessageLengthOrInvalidFormat",
                    0x24: "requestSequenceError",
                    0x31: "requestOutOfRange",
                    0x33: "securityAccessDenied",
                    0x35: "invalidKey",
                    0x7f: "serviceNotSupportedInActiveSession",
                    0x7e: "subFunctionNotSupportedInActiveSession",
            }
    mem_base = 0x1000
    
    @staticmethod
    def get_nrc_by_name(name):
        for key, val in Diag.nrc.items():
            if val == name:
                return key
        return None
    
    @staticmethod
    def print_response(msg):
        if msg[0] != 0x7F:
            print("OK %s"%" ".join("%02X "%i for i in msg))
        else:
            print("Fail %02X %s"%(msg[1], diag.Diag.nrc[msg[2]]))

    def log(self,log):
        self.mutex.acquire()
        print("%s %s"%(self.address,log))
        self.mutex.release()

    def __init__(self, conn, addres, mutex):
        self.mutex = mutex
        self.address = addres
        self.tp = isotp.ISOTP(conn)
        self.session = 0
        self.lock = 0
        self.fw = open("fw.bin","rb").read()
        self.services = {
                    0x10: self.session_control,
                    0x23: self.read_memory,
                    0x27: self.security_access
                    }
                    
        self.tp.write([c for c in "ISO-TP fatal error. Disable this message from ISO-14229 configuration! ".encode()])
        self.log("Client connected")
        try:
            self.run()
        except ConnectionResetError:
            self.log("Client disconnected")
        
        
    def run(self):
        
        while 1:
        
            msg = None
            self.log("Wait Diag CMD")
            while msg is None:
                msg = self.tp.read()
            
            self.log(" ".join(["%02X "%i for i in msg]))
            
            if msg[0] > 0x3f:
                self.log("Invalid command %x"%msg[0])
                continue
            
            if msg[0] not in [0x10, 0x23, 0x27]:
                self.tp.write([0x7F, msg[0], Diag.get_nrc_by_name("serviceNotSupported")])
                self.log("Service not suported %x"%msg[0])
                continue
            
            if len(msg) < 2:
                self.tp.write([0x7F, msg[0], Diag.get_nrc_by_name("incorrectMessageLengthOrInvalidFormat")])
                self.log("Incorrect msg len %d"%(len(msg)))
                continue
            
            status, data = self.services[msg[0]](msg[1:])
            if status:
                self.tp.write([msg[0] + 0x40] + data)
                if len(data) > 10:
                    data = data[:10]
                self.log("Positive resonse %s"%' '.join(map(hex,data)))
            else:
                self.tp.write([0x7F, msg[0], Diag.get_nrc_by_name(data)])
                self.log("Negative resonse %s" % data)

    def session_control(self, data):
        if data[0] not in [1,2]:
            return False, "subFunctionNotSupported"
                
        self.session = data[0]
        self.lock = 0
        
        return True,[data[0]]
            
    def security_access(self, data):
        if data[0] not in [1,2]:
            return False, "subFunctionNotSupported"
        
        if self.session != 0x02:
            return False, "subFunctionNotSupportedInActiveSession"
            
        if data[0] == 1:
            self.lock = 1
            return True, [0x01, 0x53, 0x5F, 0xA3, 0x85]
        
        if self.lock != 1:
            return False, "requestSequenceError"
            
        if len(data) != 5:
            return False, "incorrectMessageLengthOrInvalidFormat"
            
        if data[4] != 0x85:
            return False, "invalidKey"
        
        self.lock = 2
        return True, [data[0]]
        
    def read_memory(self, data):
        
        if self.session != 0x02:
            return False, "serviceNotSupportedInActiveSession"
            
        if self.lock != 2:
            return False, "securityAccessDenied"
            
        addr_size,size_size = divmod(data[0], 0x10)
        
        if len(data) != addr_size + size_size + 1:
            return False, "incorrectMessageLengthOrInvalidFormat"
            
        addr = reduce(lambda x,y:0x100*x+y,data[1 : addr_size + 1])
        size = reduce(lambda x,y:0x100*x+y,data[addr_size + 1 : addr_size + size_size + 1])
        
        
        if size > 0xFFE or addr < Diag.mem_base or addr + size > Diag.mem_base + len(self.fw) :
            return False, "requestOutOfRange"
        
        self.log("Read Memory %s %s"%(hex(addr), hex(size)))
        
        return True ,[x for x in self.fw[addr - Diag.mem_base: addr - Diag.mem_base + size]]
      