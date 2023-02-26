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


class BGPError(Exception):
    def __init__(self, message, errno = None):
        self.message = message
        self.errno = errno


class BGPPacketError(BGPError):
    pass


class BGPPacketHasNoMessagesError(BGPError):
    pass


class BGPMessageError(BGPError):
    pass


class BGPMessageFactoryError(BGPError):
    pass


class BGPOptionalParameterFactoryError(BGPError):
    pass


class BGPCapabilityFactoryError(BGPError):
    pass


class BGPWithdrawnPrefixError(BGPError):
    pass


class BGPUpdateAttributeFactoryError(BGPError):
    pass


class BGPRouteInitializeError(BGPError):
    pass


class BGPRouteConvertionError(BGPError):
    pass


class BGPNLRIError(BGPError):
    pass


class BGPUpdateASPathSegmentFactoryError(BGPError):
    pass