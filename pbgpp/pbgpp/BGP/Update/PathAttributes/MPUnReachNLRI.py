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

class PathAttributeMPUnReachNLRI(BGPPathAttribute):
    def __init__(self, payload):
        BGPPathAttribute.__init__(self, payload)
        self.type = BGPStatics.UPDATE_ATTRIBUTE_MP_UNREACH_NLRI
        
        try:
            # Parse Address Family Identifier
            self.AFI = struct.unpack('!H', payload[0:2])[0] # 1 for IPv4, 2 for IPv6

            # Parse subsequent address family identifier (SAFI)
            self.SAFI = struct.unpack('!B', payload[2:3])[0]
            
            # Parse withdrawn routes
            self.withdrawnRoutes = []
            routesStart = 3
            while routesStart < len(payload)-1:
                tmpPrefixLength = struct.unpack('!B', payload[routesStart:1+routesStart])[0]
                numBytesToFetch = int(tmpPrefixLength/8)
                if numBytesToFetch == 0:
                    routesStart += 1
                    continue
                
                tmpNLRI = payload[routesStart+1:routesStart+numBytesToFetch+1].hex()
                self.withdrawnRoutes.append(":".join(tmpNLRI[i:i+4].lstrip('0') for i in range(0, len(tmpNLRI), 4)) + "::/" + str(tmpPrefixLength))
                routesStart += numBytesToFetch + 1
        except Exception as e:
            print(str(e))
            pass

        self.__parse()

    def __str__(self):
        return_string = ""
        first = True

        for mp_unreach_nlri in self.withdrawnRoutes:
            if first:
                first = False
                return_string += str(mp_unreach_nlri)
                continue

            return_string += ", " + str(mp_unreach_nlri)
        return "" if len(return_string) == 0 else return_string

    def __parse(self):
        self.parsed = True
        self.error = False

    def json(self):
        r = {
            "type_string": "MPUnreachNLRI",
            "withdrawn_routes_mpunreach": []
        }

        for route in self.withdrawnRoutes:
            r["withdrawn_routes_mpunreach"].append(route)

        return r
