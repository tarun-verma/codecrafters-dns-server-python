import socket

class DNSPacket:
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
        '''
        A lot of byte setting here. Understand >> and << as bit shifts: x >> 8 will basically move x's bits 8 times to the right
        which will essentially flush the final 8 bits. When we do a logical AND of this value with all 1s, i.e., (x >> 8) & 0xFF,
        we end up extracting those particular bits and pad them into a byte.
        '''
        # set PID
        self.header[0] = (ID >> 8) & 0xFF
        self.header[1] = ID & 0xFF

        #set flags
        flags = (QR << 15) | (OPCODE << 11) | (AA << 10) | (TC << 9) | (RD << 8) | (RA << 7) | (Z << 4) | (RCODE)
        self.header[2] = (flags >> 8) & 0xFF
        self.header[3] = flags & 0xFF

        #set QDCOUNT
        self.header[4] = (QDCOUNT >> 8) & 0xFF
        self.header[5] = QDCOUNT & 0xFF

        #set ANCOUNT
        self.header[6] = (ANCOUNT >> 8) & 0xFF
        self.header[7] = ANCOUNT & 0xFF

        #set NSCOUNT
        self.header[8] = (NSCOUNT >> 8) & 0xFF
        self.header[9] = NSCOUNT & 0xFF

        #set ARCOUNT
        self.header[10] =(ARCOUNT >> 8) & 0xFF
        self.header[11] = ARCOUNT & 0xFF

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
        self.question.append((QTYPE >> 8) & 0xFF)
        self.question.append(QTYPE & 0xFF)

        # Set QCLASS
        self.question.append((QCLASS >> 8) & 0xFF)
        self.question.append(QCLASS & 0xFF)

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
        self.answer.append((TYPE >> 8) & 0xFF)
        self.answer.append(TYPE & 0xFF)

        # CLASS
        self.answer.append((CLASS >> 8) & 0xFF)
        self.answer.append(CLASS & 0xFF)

        # TTL
        self.answer.append((TTL >> 24) & 0xFF)
        self.answer.append((TTL >> 16) & 0xFF)
        self.answer.append((TTL >> 8) & 0xFF)
        self.answer.append(TTL & 0xFF)

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

def list_of_domains(packet, qdcount):
    '''
    This is the function to understand!
    Basically, this unpacks a compressed question section inside a DNS packet.
    It looks at the QDCOUNT from the DNS query header, and iterates accordingly.
    In every iteration, it checks for compression, and if found, jumps to the domain name indicated by the address.
    The goal is to essentially unpack the domains, since we need to provide answers for each of them.
    '''
    domain_names = []
    j = 12  # Questions start at byte 12

    for _ in range(qdcount):
        domain_name = []
        while packet[j] != 0:  # Stop at null terminator, since that's what separates each domain name in a question
            length = packet[j]  # Each component of a domain name has its length encoded first, so www.google.com will be 3www6google3com

            if length >= 0xC0: # bin(0xC0) means 0b11000000 - in DNS spec, if first two bits of length are set to 11, it indicates compression.
                '''
                This can be a bit tricky to understand but basically: the remaining 6 bits (after 11) and the 8 bits (1 byte) following packet[j]
                indicate the address we have to jump to to fetch the domain name.
                packet(j) & 0x3F (0b111111) gives out the 6 bits. When we shift it to the left by 8,
                we create space of the remaining 8 bits which combined will give us the pointer to jump to.
                '''
                offset = (packet[j] & 0x3F) << 8 | packet[j+1]
                length = packet[offset] # we have now jumped to the beginning of the domain name, which has the length
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
    forwarder_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            ID = int.from_bytes(buf[0:2])
            QDCOUNT = int.from_bytes(buf[4:6])

            # Flags
            FLAGS = int.from_bytes(buf[2:4])  # Read the original FLAGS field
            OPCODE = (FLAGS >> 11) & 0b1111
            RD = (FLAGS >> 8) & 0b1  # Extract the RD bit

            if OPCODE == 0:
                RCODE = 0
            else:
                RCODE = 4  # Not implemented

            domains = list_of_domains(buf, QDCOUNT)

            questions, answers = bytearray(), bytearray()

            adnsobject = DNSPacket()
            adnsobject.set_header(ID=ID, QR=1, QDCOUNT=QDCOUNT, ANCOUNT=QDCOUNT, RD=RD, OPCODE=OPCODE, RCODE=RCODE)
            A_HEADER = adnsobject.get_header()

            for domain in domains:
                offset = 12
                qdnsobject = DNSPacket()
                qdnsobject.set_question(QNAME=domain, QTYPE=1, QCLASS=1)
                qdnsobject.set_header(ID=ID, QDCOUNT=1)
                header = qdnsobject.get_header()
                question = qdnsobject.get_question()
                questions.extend(question)
                offset += len(question)
                querypacket = header + question
                forwarder_socket.sendto(querypacket, ("127.0.0.1", 5354))
                answer, resolver = forwarder_socket.recvfrom(512)
                answer = answer[offset:]
                answers.extend(answer)


            response_packet = A_HEADER + questions + answers
            udp_socket.sendto(response_packet, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break

if __name__ == "__main__":
    main()
