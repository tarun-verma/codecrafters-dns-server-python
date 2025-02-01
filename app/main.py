import socket

class DNSMessage:
    def __init__(self, 
                 header=bytearray(12), 
                 question=bytearray(12), 
                 answer=bytearray(12),
                 authority=bytearray(12),
                 space=bytearray(12) 
                 ):
        self.header = header
        self.question = question
        self.answer = answer
        self.authority = authority
        self.space = space
    
    def set_header(self,
                   ID=0,
                   QR=0,
                   OPCODE=0,
                   AA=0,
                   TC=0,
                   RD=0,
                   RA=0,
                   Z=0,
                   RCODE=0,
                   QDCOUNT=0,
                   ANCOUNT=0,
                   NSCOUNT=0,
                   ARCOUNT=0
                   ):
        # set PID
        high_byte = (ID >> 8) & 0xFF
        low_byte = ID & 0xFF
        self.header[0] = high_byte
        self.header[1] = low_byte

        #set flags
        flags = (QR << 15) | (OPCODE << 11) | (AA << 10) | (TC << 9) | (RD << 8) | (RA << 7) | (Z << 4) | (RCODE)
        high_byte = (flags >> 8) & 0xFF
        low_byte = flags & 0xFF
        self.header[2] = high_byte
        self.header[3] = low_byte

        #set QDCOUNT
        high_byte = (QDCOUNT >> 8) & 0xFF
        low_byte = QDCOUNT & 0xFF
        self.header[4] = high_byte
        self.header[5] = low_byte

        #set ANCOUNT
        high_byte = (ANCOUNT >> 8) & 0xFF
        low_byte = ANCOUNT & 0xFF
        self.header[6] = high_byte
        self.header[7] = low_byte

        #set NSCOUNT
        high_byte = (NSCOUNT >> 8) & 0xFF
        low_byte = NSCOUNT & 0xFF
        self.header[8] = high_byte
        self.header[9] = low_byte

        #set ARCOUNT
        high_byte = (ARCOUNT >> 8) & 0xFF
        low_byte = ARCOUNT & 0xFF
        self.header[8] = high_byte
        self.header[9] = low_byte
    
    def get_header(self):
        return self.header

def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")
    
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            dnsmsg = DNSMessage()
            dnsmsg.set_header(1234,1)
            header = dnsmsg.get_header()
    
            response = header
    
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break

if __name__ == "__main__":
    main()
