#
# This file is part of PCAP BGP Parser (pbgpp)
#
# Copyright 2016-2017 DE-CIX Management GmbH
# Author: Tobias Hannaske <tobias.hannaske@de-cix.net>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import struct
from pbgpp.PCAP.Information import PCAPLayer3Information


class PCAPIPV6:
    PROTO_TCP = 0x0006
    BITMASK_IP_HEADER_LENGTH = 0xf

    def __init__(self, payload):
        # Assign variables
        self.payload = payload
        self.protocol = None
        self.addresses = None

        self.header_length = 40
        self.version = None
        self.total_length = None

        # Start parsing
        self.__parse()

    def __parse(self):
        # We dont get version length in IPv6

        self.total_length = struct.unpack("!H", self.payload[4:6])[0]
        self.protocol = struct.unpack("!B", self.payload[6:7])[0]
        
        tmpIPv6src = self.payload[8:24].hex() 
        IPv6src = ":".join(tmpIPv6src[i:i+4].lstrip('0') for i in range(0, len(tmpIPv6src), 4)) 
        
        tmpIPv6dst = self.payload[24:40].hex()
        IPv6dst = ":".join(tmpIPv6dst[i:i+4].lstrip('0') for i in range(0, len(tmpIPv6dst), 4))
        self.addresses = PCAPLayer3Information(IPv6src, IPv6dst, 6)

    def get_protocol(self):
        return self.protocol

    def get_addresses(self):
        return self.addresses

    def get_ip_payload(self):
        return self.payload[self.header_length:]
