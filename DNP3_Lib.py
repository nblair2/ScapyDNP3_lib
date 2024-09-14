from scapy.all import *
from crccheck.crc import Crc16Dnp

'''
## Copyright

* updated 2024
* original 2014-2016 N.R Rodofile
* licensed under the GPLv3.
'''

# CONSTANTS for DNP3
bitState = {1: "SET", 0: "UNSET"}
stations = {1: "MASTER", 0: "OUTSTATION"}

MASTER = 1
OUTSTATION = 0
SET = 1
UNSET = 0
dnp3_port = 20000

Transport_summary = "Seq:%DNP3Transport.SEQUENCE% "
Application_Rsp_summary = "Response %DNP3ApplicationResponse.FUNC_CODE% "
Application_Req_summary = "Request %DNP3ApplicationRequest.FUNC_CODE% "
DNP3_summary = "From %DNP3.SOURCE% to %DNP3.DESTINATION% "

applicationFunctionCode = {
    0: "CONFIRM",
    1: "READ",
    2: "WRITE",
    3: "SELECT",
    4: "OPERATE",
    5: "DIRECT_OPERATE",
    6: "DIRECT_OPERATE_NR",
    7: "IMMED_FREEZE",
    8: "IMMED_FREEZE_NR",
    9: "FREEZE_CLEAR",
    10: "FREEZE_CLEAR_NR",
    11: "FREEZE_AT_TIME",
    12: "FREEZE_AT_TIME_NR",
    13: "COLD_RESTART",
    14: "WARM_RESTART",
    15: "INITIALIZE_DATA",
    16: "INITIALIZE_APPL",
    17: "START_APPL",
    18: "STOP_APPL",
    19: "SAVE_CONFIG",
    20: "ENABLE_UNSOLICITED",
    21: "DISABLE_UNSOLICITED",
    22: "ASSIGN_CLASS",
    23: "DELAY_MEASURE",
    24: "RECORD_CURRENT_TIME",
    25: "OPEN_FILE",
    26: "CLOSE_FILE",
    27: "DELETE_FILE",
    28: "GET_FILE_INFO",
    29: "AUTHENTICATE_FILE",
    30: "ABORT_FILE",
    31: "ACTIVATE_CONFIG",
    32: "AUTHENTICATE_REQ",
    33: "AUTH_REQ_NO_ACK",
    129: "RESPONSE",
    130: "UNSOLICITED_RESPONSE",
    131: "AUTHENTICATE_RESP",
}

objectPrefix = {
    0x00: "Objects Packed without an index prefix",
    0x01: "Objects prefixed with 1-octet index",
    0x02: "Objects prefixed with 2-octet index",
    0x03: "Objects prefixed with 4-octet index",
    0x04: "Objects prefixed with 1-cotet object size",
    0x05: "Objects prefixed with 2-cotet object size",
    0x06: "Objects prefixed with 4-cotet object size",
    0x07: "Reserved for future use",
}

rangeSpecifier = {
    0x00: "Range field contains 1-octet start and stop indexes",
    0x01: "Range field contains 2-octet start and stop indexes",
    0x02: "Range field contains 4-octet start and stop indexes",
    0x03: "Range field contains 1-octet start and stop virtual addresses",
    0x04: "Range field contains 2-octet start and stop virtual addresses",
    0x05: "Range field contains 4-octet start and stop virtual addresses",
    0x06: "No range field is used",
    0x07: "Range field contains 1-octet count of objects",
    0x08: "Range field contains 2-octet count of objects",
    0x09: "Range field contains 4-octet count of objects",
    0x0A: "Reserved for future use",
    0x0B: "Variable format qualifier, range field contains 1-octet count of objects",
    0x0C: "Reserved for future use",
    0x0D: "Reserved for future use",
    0x0E: "Reserved for future use",
    0x0F: "Reserved for future use",
}


# FUNCTIONS
## CRC
def crcDNP(data):
    c = Crc16Dnp()
    c.process(data)
    return c.final().to_bytes(2, "little")

def CRC_check(chunk, crc):
    chunk_crc = crcDNP(chunk)
    crc = struct.unpack('<H', crc)[0]
    if crc == chunk_crc:
        return True, crc
    else:
        return False, crc

def update_data_chunk_crc(chunk):
    crc = crcDNP(chunk[:-2])
    chunk = chunk[:-2] + struct.pack('<H', crc)
    return chunk

def add_CRC_payload(payload):
    if len(payload) > 18:
        chunk = payload[:18]
        chunk = update_data_chunk_crc(chunk)
        payload = chunk + payload[18:]

    else:
        chunk = payload[:-2]
        chunk = update_data_chunk_crc(chunk)
        payload = chunk
    return payload



# CLASSES
## DNP3
### DNP3 Application
#### DNP3 Application Requests
class DNP3ApplicationControl(Packet):
    fields_desc = [
        BitEnumField("FIN", 1, 1, bitState),
        BitEnumField("FIR", 1, 1, bitState),
        BitEnumField("CON", 1, 1, bitState),
        BitEnumField("UNS", 1, 1, bitState),
        BitField("SEQ", 1, 4),
    ]

    def extract_padding(self, p):
        return "", p

class DNP3ApplicationReadRequestObject(Packet):
    name= "DNP3_Application_Read_Request_Object"

    dataClass = {
        0x01: "Class 0",
        0x02: "Class 1",
        0x03: "Class 2",
        0x04: "Class 3",
    }

    fields_desc = [
        ByteField("OBJECT_GROUP", None),
        BitEnumField("CLASS", None, 8, dataClass),
        BitField("RESERVED", 0, 1,),
        BitEnumField("OBJECT_PREFIX_CODE", 0, 3, objectPrefix),
        BitEnumField("RANGE_SPECIFIER_CODE", 6, 4, rangeSpecifier),
    ]

    def extract_padding(self, p):
        return "", p

class DNP3ApplicationRequest(Packet):
    name = "DNP3_Application_request"
    fields_desc = [
        PacketField("APP_CONTROL", DNP3ApplicationControl(), DNP3ApplicationControl),
        BitEnumField("FUNC_CODE", 1, 8, applicationFunctionCode),
        PacketListField("READ_REQ_OBJ", None, DNP3ApplicationReadRequestObject),
    ]

    def mysummary(self):
        if isinstance(self.underlayer.underlayer, DNP3):
            return self.underlayer.underlayer.sprintf(DNP3_summary + Transport_summary + Application_Req_summary)
        if isinstance(self.underlayer, DNP3Transport):
            return self.underlayer.sprintf(Transport_summary + Application_Req_summary)
        else:
            return self.sprintf(Application_Req_summary)

    def post_build(self, pkt, pay):
        if self.FUNC_CODE == 0x01:
            for request in self.READ_REQ_OBJ:
                pay += request.build()
        return super().post_build(pkt, pay)

#### DNP3 Application Response
class DNP3ApplicationIIN(Packet):
    name = "DNP3_Application_IIN"
    fields_desc = [
        BitEnumField("DEVICE_RESTART", UNSET, 1, bitState),
        BitEnumField("DEVICE_TROUBLE", UNSET, 1, bitState),
        BitEnumField("LOCAL_CONTROL", UNSET, 1, bitState),
        BitEnumField("NEED_TIME", UNSET, 1, bitState),
        BitEnumField("CLASS_3_EVENTS", UNSET, 1, bitState),
        BitEnumField("CLASS_2_EVENTS", UNSET, 1, bitState),
        BitEnumField("CLASS_1_EVENTS", UNSET, 1, bitState),
        BitEnumField("BROADCAST", UNSET, 1, bitState),
        BitEnumField("RESERVED_1", UNSET, 1, bitState),
        BitEnumField("RESERVED_2", UNSET, 1, bitState),
        BitEnumField("CONFIG_CORRUPT", UNSET, 1, bitState),
        BitEnumField("ALREADY_EXECUTING", UNSET, 1, bitState),
        BitEnumField("EVENT_BUFFER_OVERFLOW", UNSET, 1, bitState),
        BitEnumField("PARAMETER_ERROR", UNSET, 1, bitState),
        BitEnumField("OBJECT_UNKNOWN", UNSET, 1, bitState),
        BitEnumField("NO_FUNC_CODE_SUPPORT", UNSET, 1, bitState),
    ]

    def extract_padding(self, p):
        return "", p

groupVarImplemented = [
    [1, 2]
]

class DNP3ApplicationResponseDataObjectG1V2(Packet):
    name= "Binary_Input_Point"
    fields_desc = [
       BitEnumField("POINT_VALUE", UNSET, 1, bitState), 
       BitEnumField("RESERVERD", UNSET, 1, bitState), 
       BitEnumField("CHATTER_FILTER", UNSET, 1, bitState), 
       BitEnumField("LOCAL_FORCE", UNSET, 1, bitState), 
       BitEnumField("REMOTE_FORCE", UNSET, 1, bitState), 
       BitEnumField("COMM_FAIL", UNSET, 1, bitState), 
       BitEnumField("RESTART", UNSET, 1, bitState), 
       BitEnumField("ONLINE", UNSET, 1, bitState), 
    ]

    def extract_padding(self, p):
        return "", p

class DNP3ApplicationResponseData(Packet):
    name= "DNP3_Application_Response_Data"
    fields_desc = [
        # Standard fields
        ByteField("GROUP", None),
        ByteField("VARIATION", None),
        BitField("RESERVED", 0, 1,),
        BitEnumField("OBJECT_PREFIX_CODE", 0, 3, objectPrefix),
        BitEnumField("RANGE_SPECIFIER_CODE", 6, 4, rangeSpecifier),
        # Conditional fields based on header
            # Range
                # Start and stop indexes of various size
        ConditionalField(MultipleTypeField([
            [NBytesField("RANGE_START", 0, 1), lambda pkt: pkt.RANGE_SPECIFIER_CODE == 0x00],
            [NBytesField("RANGE_START", 0, 2), lambda pkt: pkt.RANGE_SPECIFIER_CODE == 0x01],
            [NBytesField("RANGE_START", 0, 4), lambda pkt: pkt.RANGE_SPECIFIER_CODE == 0x02],
                    # virtual
            [NBytesField("RANGE_START", 0, 1), lambda pkt: pkt.RANGE_SPECIFIER_CODE == 0x03],
            [NBytesField("RANGE_START", 0, 2), lambda pkt: pkt.RANGE_SPECIFIER_CODE == 0x04],
            [NBytesField("RANGE_START", 0, 4), lambda pkt: pkt.RANGE_SPECIFIER_CODE == 0x05],
            ], NBytesField("RANGE_START", 0, 1)), lambda pkt: pkt.RANGE_SPECIFIER_CODE in [0x00, 0x01, 0x02, 0x03, 0x04, 0x05]),
        ConditionalField(MultipleTypeField([
            [NBytesField("RANGE_STOP", 0, 1), lambda pkt: pkt.RANGE_SPECIFIER_CODE == 0x00],
            [NBytesField("RANGE_STOP", 0, 2), lambda pkt: pkt.RANGE_SPECIFIER_CODE == 0x01],
            [NBytesField("RANGE_STOP", 0, 4), lambda pkt: pkt.RANGE_SPECIFIER_CODE == 0x02],
                    # virtual
            [NBytesField("RANGE_STOP", 0, 1), lambda pkt: pkt.RANGE_SPECIFIER_CODE == 0x03],
            [NBytesField("RANGE_STOP", 0, 2), lambda pkt: pkt.RANGE_SPECIFIER_CODE == 0x04],
            [NBytesField("RANGE_STOP", 0, 4), lambda pkt: pkt.RANGE_SPECIFIER_CODE == 0x05],
            ], NBytesField("RANGE_STOP", 0, 1)), lambda pkt: pkt.RANGE_SPECIFIER_CODE in [0x00, 0x01, 0x02, 0x03, 0x04, 0x05]),
                # count of objects
        ConditionalField(MultipleTypeField([
            [NBytesField("RANGE_COUNT", 0, 1), lambda pkt: pkt.RANGE_SPECIFIER_CODE == 0x07],
            [NBytesField("RANGE_COUNT", 0, 2), lambda pkt: pkt.RANGE_SPECIFIER_CODE == 0x08],
            [NBytesField("RANGE_COUNT", 0, 4), lambda pkt: pkt.RANGE_SPECIFIER_CODE == 0x09],
                    # variable format, range field 1 octet count
            [NBytesField("RANGE_COUNT", 0, 1), lambda pkt: pkt.RANGE_SPECIFIER_CODE == 0x0B],
            ], NBytesField("RANGE_COUNT", 0, 1)), lambda pkt: pkt.RANGE_SPECIFIER_CODE in [0x07, 0x08, 0x09, 0x0B]),
        # Data Fields
        #PacketListField("asdf", None, DNP3ApplicationResponseDataObjectG1V2, count_from=lambda pkt: pkt.RANGE_STOP - pkt.RANGE_START + 1)
       #  ConditionalField(MultipleTypeField([
       #       [PacketListField("BINARY_INPUT_w_FLAGS", None, DNP3ApplicationResponseDataObjectG1V2,
       #                count_from=lambda pkt: pkt.RANGE_STOP - pkt.RANGE_START + 1), 
       #           lambda pkt: pkt.GROUP == 0x01 and pkt.VARIATION == 0x02],
       #       ], ByteField("DATA_OBJECT", None)), lambda pkt: [pkt.GROUP, pkt.VARIATION] in groupVarImplemented)
    ]

class DNP3ApplicationResponse(Packet):
    name = "DNP3_Application_response"
    fields_desc = [
        PacketField("APP_CONTROL", DNP3ApplicationControl(), DNP3ApplicationControl),
        BitEnumField("FUNC_CODE", 1, 8, applicationFunctionCode),
        PacketField("IIN", DNP3ApplicationIIN(), DNP3ApplicationIIN),
        PacketListField("RESPONSE_OBJ", None, DNP3ApplicationResponseData),
    ]

    def extract_padding(self, p):
        return "", p

    def mysummary(self):
        if isinstance(self.underlayer.underlayer, DNP3):
            print(self.FUNC_CODE.SEQ, "Hello")
            return self.underlayer.underlayer.sprintf(DNP3_summary + Transport_summary + Application_Rsp_summary)
        if isinstance(self.underlayer, DNP3Transport):
            return self.underlayer.sprintf(Transport_summary + Application_Rsp_summary)
        else:
            return self.sprintf(Application_Req_summary)

### DNP3 Transport
class DNP3Transport(Packet):
    name = "DNP3_Transport"
    fields_desc = [
        BitEnumField("FIN", 1, 1, bitState),
        BitEnumField("FIR", 1, 1, bitState),
        BitField("SEQUENCE", 0, 6),
    ]

    def guess_payload_class(self, payload):

        if isinstance(self.underlayer, DNP3):
            DIR = self.underlayer.CONTROL.DIR

            if DIR == MASTER:
                return DNP3ApplicationRequest

            if DIR == OUTSTATION:
                return DNP3ApplicationResponse
        else:
            return Packet.guess_payload_class(self, payload)


class DNP3HeaderControl(Packet):
    name = "DNP3_Header_control"

    controlFunctionCodePri = {
        0: "RESET_LINK_STATES",
        2: "TEST_LINK_STATES",
        3: "CONFIRMED_USER_DATA",
        4: "UNCONFIRMED_USER_DATA",
        9: "REQUEST_LINK_STATUS",
    }

    controlFunctionCodeSec = {
        0: "ACK",
        1: "NACK",
        11: "LINK_STATUS",
        15: "NOT_SUPPORTED",
    }

    cond_field = [
        BitEnumField("FCB", 0, 1, bitState),
        BitEnumField("FCV", 0, 1, bitState),
        BitEnumField("FUNC_CODE_PRI", 4, 4,  controlFunctionCodePri),
        BitEnumField("reserved", 0, 1, bitState),
        BitEnumField("DFC", 0, 1, bitState),
        BitEnumField("FUNC_CODE_SEC", 4, 4,  controlFunctionCodeSec),
    ]

    fields_desc = [
        BitEnumField("DIR", MASTER, 1, bitState),  # 9.2.4.1.3.1 DIR bit field
        BitEnumField("PRM", MASTER, 1,  bitState),  # 9.2.4.1.3.2 PRM bit field
        ConditionalField(cond_field[0], lambda x:x.PRM == MASTER),
        ConditionalField(cond_field[1], lambda x:x.PRM == MASTER),
        ConditionalField(cond_field[2], lambda x:x.PRM == MASTER),
        ConditionalField(cond_field[3], lambda x:x.PRM == OUTSTATION),
        ConditionalField(cond_field[4], lambda x:x.PRM == OUTSTATION),
        ConditionalField(cond_field[5], lambda x:x.PRM == OUTSTATION),
    ]

    def extract_padding(self, p):
        return "", p


class DNP3(Packet):
    name = "DNP3"
    fields_desc = [
        XShortField("START", 0x0564),
        ByteField("LENGTH", 32),
        PacketField("CONTROL", None, DNP3HeaderControl),
        LEShortField("DESTINATION", None),
        LEShortField("SOURCE", None),
        XShortField("CRC", None),
    ]

    data_chunks = []  # Data Chunks are 16 octets
    data_chunks_crc = []
    chunk_len = 18
    data_chunk_len = 16

    def show_data_chunks(self):
        for i in range(len(self.data_chunks)):
            print("\tData Chunk", i, "Len", len(self.data_chunks[i]),\
                "CRC (", hex(struct.unpack('<H', self.data_chunks_crc[i])[0]), ")")


    def add_data_chunk(self, chunk):
        chunk = update_data_chunk_crc(chunk)
        self.data_chunks.append(chunk[:-2])
        self.data_chunks_crc.append(chunk[-2:])

    def post_build(self, pkt, pay):
        cnk_len = self.chunk_len
        pay_len = len(pay)
        pkt_len = len(pkt)
        total = pkt_len + pay_len
        chunks = pay_len / cnk_len  # chunk size
        #chunks = total / cnk_len  # chunk size
        last_chunk = pay_len % cnk_len

        if last_chunk > 0:
                chunks += 1

        if pay_len == 3 and self.CONTROL.DIR == MASTER:

            # No IIN in Application layer and empty Payload
            pay = pay + struct.pack('H', crcDNP(pay))

        if pay_len == 5 and self.CONTROL.DIR == OUTSTATION:

            # IIN in Application layer and empty Payload
            pay = pay + struct.pack('H', crcDNP(pay))

        if self.LENGTH == None:

             # Remove length , crc, start octets as part of length
            length = (len(pkt+pay) - ((chunks * 2) + 1 + 2 + 2))
            print(pkt)
            pkt = pkt[:2] + struct.pack('<B', length) + pkt[3:]

        CRC = crcDNP(pkt[:8])  # use only the first 8 octets

        if self.CRC == None:
            pkt = pkt[:2] + CRC
            # pkt = pkt[:-2] + struct.pack('H', CRC)

        else:
            if CRC != self.CRC:
                pkt = pkt[:2] + CRC
                # pkt = pkt[:-2] + struct.pack('H', CRC)

        self.data_chunks = []
        self.data_chunks_crc = []

        remaining_pay = pay_len
        for c in range(chunks):
            index = c * cnk_len  # data chunk

            if (remaining_pay < cnk_len) and (remaining_pay > 0):
                self.add_data_chunk(pay[index:])
                break  # should be the last chunk
            else:
                self.add_data_chunk(pay[index:index + cnk_len])
                remaining_pay -= cnk_len

        payload = ''
        for chunk in range(len(self.data_chunks)):
            payload = payload + self.data_chunks[chunk] + self.data_chunks_crc[chunk]
        #  self.show_data_chunks()  # --DEBUGGING
        return pkt+payload

    def guess_payload_class(self, payload):
        if len(payload) > 0:
            return DNP3Transport
        else:
            return Packet.guess_payload_class(self, payload)


bind_layers(TCP, DNP3, dport=dnp3_port)
bind_layers(TCP, DNP3, sport=dnp3_port)
bind_layers(UDP, DNP3, dport=dnp3_port)
bind_layers(UDP, DNP3, sport=dnp3_port)
