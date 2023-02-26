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

from pbgpp.BGP.Statics import BGPStatics
from pbgpp.BGP.Update.PathAttribute import BGPPathAttribute
import struct
import traceback

class PathAttributeMPReachNLRI(BGPPathAttribute):
    def __init__(self, payload):
        BGPPathAttribute.__init__(self, payload)
        try:
            # Parse Address Family Identifier
            
            self.AFI = struct.unpack('!H', payload[0:2])[0] # 1 for IPv4, 2 for IPv6
            
            # Parse subsequent address family identifier (SAFI)
            self.SAFI = struct.unpack('!B', payload[2:3])[0]
            # Parse size of next hop network address
            self.nextHopSize = struct.unpack('!B', payload[3:4])[0]
            # Parse next hop network address
            tmpNextHop = payload[4:4+self.nextHopSize].hex()
            self.nextHop = ":".join(tmpNextHop[i:i+4].lstrip('0') for i in range(0, len(tmpNextHop), 4))
            
            # Set number of subnetwork points of attachment
            self.SNPA = struct.unpack('!B', payload[4+self.nextHopSize:5+self.nextHopSize])[0]
            
            self.NLRI = []
            # Parse NLRI from remaining data
            nlriStart = 5+self.nextHopSize
            while nlriStart < len(payload)-1:
                tmpPrefixLength = struct.unpack('!B', payload[nlriStart:1+nlriStart])[0]
                numBytesToFetch = int(tmpPrefixLength/8)
                #print(payload[nlriStart+1:nlriStart+numBytesToFetch+1].hex())
                if numBytesToFetch == 0:
                    nlriStart += numBytesToFetch + 1
                    continue
                
                tmpNLRI = payload[nlriStart+1:nlriStart+numBytesToFetch+1].hex()
                self.NLRI.append(":".join(tmpNLRI[i:i+4].lstrip('0') for i in range(0, len(tmpNLRI), 4)) + "::/" + str(tmpPrefixLength))
                nlriStart += numBytesToFetch + 1

        except Exception as e:
           pass 
        # Set network layer reachability information
        self.type = BGPStatics.UPDATE_ATTRIBUTE_MP_REACH_NLRI

        self.__parse()

    def __str__(self):
        return_string = ""
        first = True

        for mp_reach_nlri in self.NLRI:
            if first:
                first = False
                return_string += str(mp_reach_nlri)
                continue

            return_string += ", " + str(mp_reach_nlri)
        return_string += "\n|--- Next Hop: " + self.nextHop
        return "" if len(return_string) == 0 else return_string


    def __parse(self):
        self.parsed = True
        self.error = False

    def json(self):
        r = {
            "type_string": "MPReachNLRI",
            "mp_reach_nlri": [],
            "next_hop_nlri": self.nextHop
        }

        for nlri in self.NLRI:
            r["mp_reach_nlri"].append(nlri)

        return r

