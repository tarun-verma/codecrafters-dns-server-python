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

        if TYPE == 1:
        # Parse IP string like "8.8.8.8" → [8, 8, 8, 8]
            octets = RDATA.split('.')
            if len(octets) != 4:
                raise ValueError(f"Invalid IPv4 address: {RDATA}")

            rdata_bytes = bytes(int(part) for part in octets)
            # For an A record, RDLENGTH is always 4
            LENGTH = 4
        else:
            # For other record types, you might store RDATA as text or more advanced encoding
            rdata_bytes = RDATA.encode('utf-8')
            LENGTH = len(rdata_bytes)

        # 5. Write the RDLENGTH
        self.answer.append((LENGTH >> 8) & 0xFF)
        self.answer.append(LENGTH & 0xFF)

        # 6. Write the RDATA bytes
        self.answer.extend(rdata_bytes)
    
    def get_answer(self):
        return self.answer


def parse_domain_name(domain_bytes):
    domain_name = []
    i = 0
    while i < len(domain_bytes):
        length = domain_bytes[i]
        if length == 0:
            break
        i += 1
        domain_name.append(domain_bytes[i:length+i].decode('utf-8'))
        i += length
    return ".".join(domain_name)

def list_of_domains(packet, qdcount):
    domain_names = []
    j = 12  # Questions start at byte 12

    for _ in range(qdcount):
        domain_name = []
        while packet[j] != 0:  # Stop at null terminator
            length = packet[j]

            if length >= 0xC0:
                offset = (packet[j] & 0x3F) << 8 | packet[j+1]
                length = packet[offset]
                j = offset + 1
                ptr = j
            else:
                j += 1
                ptr = j
            # Read label and append to domain name
            domain_name.append(packet[ptr:ptr+length].decode('utf-8'))
            j += length  # Move past label
        j += 1  # Move past the null terminator
        domain_names.append(".".join(domain_name))
        # Skip QTYPE (2 bytes) and QCLASS (2 bytes)
        j += 4
        
    return domain_names

def main():
    # You can use `print` statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")
    
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            # Parse individual values inside the FLAGS
            ID = int.from_bytes(buf[0:2])
            QDCOUNT = int.from_bytes(buf[4:6])
            FLAGS = int.from_bytes(buf[2:4])  # Read the original FLAGS field
            RD = (FLAGS >> 8) & 1  # Extract the RD bit
            OPCODE = (FLAGS >> 11) & 0b1111
            if OPCODE == 0:
                RCODE = 0
            else:
                RCODE = 4  # Not implemented

            domains = list_of_domains(buf, QDCOUNT)
            
            dnsmainmsg = DNSMessage()
            dnsmainmsg.set_header(ID=ID, QR=1, OPCODE=OPCODE, RCODE=RCODE, RD=RD, QDCOUNT=QDCOUNT, ANCOUNT=len(domains))
 
            response = dnsmainmsg.get_header()

            questions = bytearray()
            answers = bytearray()

            print("Domains to parse: ", domains)
            print("QDCOUNT: ", QDCOUNT)

            for domain in domains:
                dnsmsg = DNSMessage()
                dnsmsg.set_question(QNAME=domain, QTYPE=1, QCLASS=1)
                questions.extend(dnsmsg.get_question())
            
            for domain in domains:
                dnsmsg = DNSMessage()
                dnsmsg.set_answer(NAME=domain, TYPE=1, CLASS=1, TTL=60, LENGTH=4, RDATA="8.8.8.8")
                answers.extend(dnsmsg.get_answer())

            print("Length of header: ", len(response))
            print("Length of questions: ", len(questions))
            print("Length of answers: ", len(answers))

            print(f"[DEBUG] Header Section Hex: {response.hex()}")
            print(f"[DEBUG] Question Section Hex: {questions.hex()}")
            print(f"[DEBUG] Answer Section Hex: {answers.hex()}")
            
            '''
            remainder = buf[12:]
            
            domain_name = parse_domain_name(remainder)

            ID = int.from_bytes(recvd_header[0:2])
            FLAGS = int.from_bytes(recvd_header[2:4])
            

            questions = list_of_domains(buf, QDCOUNT)

            print("Look here --> ", questions)

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
                              QDCOUNT=QDCOUNT, 
                              ANCOUNT=1)
            
            dnsmsg.set_question(QNAME=domain_name, QTYPE=1, QCLASS=1)
            dnsmsg.set_answer(NAME=domain_name, TYPE=1, CLASS=1, TTL=60, LENGTH=4, RDATA="8.8.8.8")

            header = dnsmsg.get_header()
            question = dnsmsg.get_question()
            answer = dnsmsg.get_answer()
            '''
            response = response + questions + answers
            response_size = len(response)
            
            print(f"[DEBUG] Final Response Hex: {response.hex()}")
            print(f"[DEBUG] Final Response Size: {len(response)} bytes")

            if response_size > 512:
                print(f"ERROR: Response too big! {response_size} bytes")
                response = response[:512]  # Truncate to fit UDP limits
            
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break

if __name__ == "__main__":
    main()
