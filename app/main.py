import socket

class DNSMessage:
    def __init__(self, 
                 header=None, 
                 question=None, 
                 answer=None,
                 authority=None,
                 space=None
                 ):
        self.header = header if header is not None else bytearray(12)
        self.question = question if question is not None else bytearray()
        self.answer = answer if answer is not None else bytearray()
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
        self.header[10] = high_byte
        self.header[11] = low_byte
    
    def get_header(self):
        return self.header
    
    def set_question(self,
                     QNAME="",
                     QTYPE=0,
                     QCLASS=0):
        # Set question name
        QNAME = QNAME.split('.')
        for token in QNAME:
            self.question.append(len(token))
            self.question.extend(token.encode('utf-8'))
        self.question.append(0)

        # Set QTYPE
        high_byte = (QTYPE >> 8) & 0xFF
        low_byte = QTYPE & 0xFF
        self.question.append(high_byte)
        self.question.append(low_byte)

        # Set QCLASS
        high_byte = (QCLASS >> 8) & 0xFF
        low_byte = QCLASS & 0xFF
        self.question.append(high_byte)
        self.question.append(low_byte)
    
    def get_question(self):
        return self.question

    def set_answer(self,
                   NAME="",
                   TYPE=0, # 2 byte
                   CLASS=0, # 2 byte
                   TTL=0, # 4 byte
                   LENGTH=0, # 2 byte
                   RDATA=""): # variable
        
        NAME = NAME.split('.')
        for token in NAME:
            self.answer.append(len(token))
            self.answer.extend(token.encode('utf-8'))
        self.answer.append(0) # null byte

        # TYPE
        high_byte = (TYPE >> 8) & 0xFF
        low_byte = TYPE & 0xFF
        self.answer.append(high_byte)
        self.answer.append(low_byte)

        # CLASS
        high_byte = (CLASS >> 8) & 0xFF
        low_byte = CLASS & 0xFF
        self.answer.append(high_byte)
        self.answer.append(low_byte)

        # TTL
        highest_byte = (TTL >> 24) & 0xFF
        higher_byte = (TTL >> 16) & 0xFF
        high_byte = (TTL >> 8) & 0xFF
        low_byte = TTL & 0xFF
        self.answer.append(highest_byte)
        self.answer.append(higher_byte)
        self.answer.append(high_byte)
        self.answer.append(low_byte)

        # LENGTH
        high_byte = (LENGTH >> 8) & 0xFF
        low_byte = LENGTH & 0xFF
        self.answer.append(high_byte)
        self.answer.append(low_byte)

        # RDATA
        self.answer.extend(RDATA.encode('utf-8'))
    
    def get_answer(self):
        return self.answer


def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")
    
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            recvd_header = buf[:12]

            ID = int.from_bytes(recvd_header[0:2])
            FLAGS = int.from_bytes(recvd_header[2:4])

            # Parse individual values inside the FLAGS
            OPCODE = (FLAGS >> 11) & 0b1111
            RD = (FLAGS >> 8) & 1
            RCODE = 0 if OPCODE == 0 else 4

            dnsmsg = DNSMessage()

            dnsmsg.set_header(ID=ID, 
                              QR=1,
                              OPCODE=OPCODE,
                              RD=RD,
                              RCODE=RCODE,
                              QDCOUNT=1, 
                              ANCOUNT=1)
            
            dnsmsg.set_question(QNAME="codecrafters.io", QTYPE=1, QCLASS=1)
            dnsmsg.set_answer(NAME="codecrafters.io", TYPE=1, CLASS=1, TTL=60, LENGTH=4, RDATA="8.8.8.8")

            header = dnsmsg.get_header()
            question = dnsmsg.get_question()
            answer = dnsmsg.get_answer()
    
            response = header + question + answer
    
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break

if __name__ == "__main__":
    main()
