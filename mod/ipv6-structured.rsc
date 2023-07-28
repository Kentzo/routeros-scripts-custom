# Usage:
#
# - $parseIP6Address ip6 [prefix length] [detail=yes]
# - $parseIP6Address ip6-prefix [detail=yes]
#
# Returns:
#
# - address (ip6): IPv6 address of the input
#   addressPrefix (ip6-prefix): IPv6 address-prefix of the input
#   prefix (ip6): Prefix of the input
#   prefixLength (num): Prefix length of the input
#
# If invoked with detail=yes, then the "detail" key will also be set to one of:
#
# - type (str): "unspecified"
#   fields (array): Address as an array of 8 integers
#
# - type (str): "loopback"
#   fields (array): Address as an array of 8 integers
#
# - type (str): "link-local"
#   fields (array): Address as an array of 8 integers
#
# - type (str): "ip4-mapped"
#   fields (array): Address as an array of 8 integers
#   ip4 (ip): Embedded IPv4 address
#
# - type (str): "ip4-compatible"
#   fields (array): Address as an array of 8 integers
#   ip4 (ip): Embedded IPv4 address
#
# - type (str): "multicast"
#   fields (array): Address as an array of 8 integers
#   flags (num): Multicast flags
#   groupID (num): Multicast group ID
#
# - type (str): "multicast"
#   fields (array): Address as an array of 8 integers
#   flags (num): Multicast flags
#   subnetPrefix (ip6): Unicast base
#   subnetPrefixLength (num): Length of the unicast base
#   groupID (num): Multicast group ID
#   [RIID] (ip): address of the embedded multicast rendezvous point; optional
#   SSM (bool): Whether multicast address is source-specific
#
# - type (str): "unicast"
#   subtype (str): "ula" if Unique Local IPv6 Unicast; otherwise "gua"
#   fields (array): Address as an array of 8 integers
#   globalID (ip6): Site identifier
#   subnetID (ip6): Subnet identifier within site
#   interfaceID (ip6): Interface identifier on a link
#

# Return IPv6 prefix mask of given length.
#
# $1 (integer): prefix length
#
# > :put [$MakeIP6PrefixMask 64]
# ffff:ffff:ffff:ffff::
:global MakeIP6PrefixMask do={
    :if (($1 < 0) or ($1 > 128)) do={ :error "$1 is invalid IPv6 mask length" }

    :local varMask ""

    :if ($1 >= 16) do={
        :set varMask "ffff"
        :for i from=1 to=(($1 / 16) - 1) step=1 do={
            :set varMask ($varMask . ":ffff")
        }
    }

    :local varRemBits ($1 % 16)

    :if ($varRemBits > 0) do={
        :if ([:len $varMask]) do={
            :set varMask ($varMask . ":")
        }

        :for i from=1 to=4 do={
            :if ($varRemBits >= 4) do={
                :set varMask ($varMask . "f")
                :set varRemBits ($varRemBits - 4)
            } else={
                :set varMask ($varMask . ({0;1;3;7}->($varRemBits % 4)))
                :set varRemBits 0
            }
        }
    }

    :if ($1 <= 112) do={
        :set varMask ($varMask . "::")
    }

    :return [:toip6 $varMask]
}

# Return IPv6 suffix mask of given length.
#
# $1 (integer): prefix length
#
# > :put [$MakeIP6PrefixMask 64]
# ::ffff:ffff:ffff:ffff
:global MakeIP6SuffixMask do={
    :global MakeIP6PrefixMask

    :if (($1 < 0) or ($1 > 128)) do={ :error "$1 is invalid IPv6 mask length" }
    :return (~[$MakeIP6PrefixMask (128 - $1)])
}

# Return given IPv6 address as an array of eight 16bit integers,
# one integer per field.
#
# $1 (ip6, str): IPv6 address
#
# > :put [$MakeIP6AddressFields 2001:db8::1]
# 8193;3512;0;0;0;0;0;1
:global MakeIP6AddressFields do={
    :local varAddr [:tostr $1]
    :local varAddrLen [:len $varAddr]

    # ::
    :if ($varAddrLen = 2) do={ :return {0 ; 0 ; 0 ; 0 ; 0 ; 0 ; 0 ; 0} }

    :local funcParseFields do={
        :local varFieldParts ({})
        :local varFieldIdx 0
        :local varDelimIdx [:find $1 ":" $varFieldIdx]

        :while ($varDelimIdx) do={
            :set varFieldParts ($varFieldParts , [:tonum "0x$[:pick $1 $varFieldIdx $varDelimIdx]"])
            :set varFieldIdx ($varDelimIdx + 1)
            :set varDelimIdx [:find $1 ":" $varFieldIdx]
        }

        :set varFieldParts ($varFieldParts , [:tonum "0x$[:pick $1 $varFieldIdx [:len $1]]"])
        :return $varFieldParts
    }

    :local varDelimIdx [:find $varAddr ":"]

    # ::x
    :if ($varDelimIdx = 0) do={
        :local varFieldsTail [$funcParseFields [:pick $varAddr 2 $varAddrLen]]
        :local varFieldsHead ({})
        :for i from=0 to=(7 - [:len varFieldsTail]) do={ :set varFieldsHead ($varFieldsHead , 0) }
        :return ($varFieldsHead , $varFieldsTail)
    }

    # x::
    :if ($varDelimIdx = ($varAddrLen - 2)) do={
        :local varFieldsHead [$funcParseFields [:pick $varAddr 0 $varDelimIdx]]
        :local varFieldsTail ({})
        :for i from=0 to=(7 - [:len varFieldsTail]) do={ :set varFieldsTail ($varFieldsTail , 0) }
        :return ($varFieldsHead , $varFieldsTail)
    }

    :set varDelimIdx [:find $varAddr "::" ($varDelimIdx - 1)]

    # x::x
    :if ([:typeof $varDelimIdx] != "nil") do={
        :local varFieldsHead [$funcParseFields [:pick $varAddr 0 $varDelimIdx]]
        :local varFieldsTail [$funcParseFields [:pick $varAddr ($varDelimIdx + 2) $varAddrLen]]
        :local varFieldsMid ({})
        :for i from=0 to=(7 - [:len $varFieldsHead] - [:len $varFieldsTail]) do={ :set varFieldsMid ($varFieldsMid , 0) }
        :return ($varFieldsHead , $varFieldsMid , $varFieldsTail)
    }

    # x:x:x:x:x:x:x:x
    :return [$funcParseFields $varAddr]
}

# Return given input as an ip6 object.
#
# $1 (array): IPv6 address as an array of fields
#
# $1 (ip6, str): IPv6 prefix
# $2 (str): MAC
#
# $1 (ip6, str): IPv6 address
#
# > :put [$MakeIP6Address ({8193;3512;0;0;0;0;0;1})]
# 2001:db8::1
#
# > :put [$MakeIP6Address fe80:: "00:00:5E:00:53:01"]
# fe80::200:5eff:fe00:5301
#
# > :put [$MakeIP6Address "2001:db8::1"]
# 2001:db8::1
:global MakeIP6Address do={
    :if ([:typeof $1] = "array") do={
        :local varHexMap [:toarray "0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F"]
        :local varDigitMask {0xf000 ; 0x0f00 ; 0x00f0 ; 0x000f}
        :local varAddr ""

        :for fieldIdx from=0 to=7 do={
            :local varFieldNum ($1->$fieldIdx)

            :if ($varFieldNum != 0) do={
                :for digitIdx from=0 to=3 do={
                    :local varDigitNum (($varFieldNum & ($varDigitMask->$digitIdx)) >> (12 - $digitIdx * 4))
                    :local varDigit ($varHexMap->$varDigitNum)
                    :set varAddr ($varAddr . $varDigit)
                }
            } else={
                :set varAddr ($varAddr . "0")
            }

            :if ($fieldIdx != 7) do={ :set varAddr ($varAddr . ":") }
        }

        :return [:toip6 $varAddr]
    }

    :local argAddr [:toip6 $1]
    :if ([:typeof $argAddr] != "ip6") do={ :error "\"$1\" is invalid IPv6 address"}

    :if (([:typeof $2] = "str") and ([:len $2] = 17)) do={
        :local varPrefixFields [$MakeIP6AddressFields $1]
        :put "$varPrefixFields"
        :local varMACFields {\
            [:tonum "0x$[:pick $2 0 2]"] ;\
            [:tonum "0x$[:pick $2 3 5]"] ;\
            [:tonum "0x$[:pick $2 6 8]"] ;\
            [:tonum "0x$[:pick $2 9 11]"] ;\
            [:tonum "0x$[:pick $2 12 14]"] ;\
            [:tonum "0x$[:pick $2 15 17]"]\
        }
        :put "$varMACFields"
        :local varEUI64Fields {\
            (((($varMACFields->0) << 8) | ($varMACFields->1)) ^ 0x0200) ;\
            ((($varMACFields->2) << 8) | 0x00ff) ;\
            (0xfe00 | ($varMACFields->3)) ;\
            ((($varMACFields->4) << 8) | ($varMACFields->5))\
        }
        :put "$varMACFields"
        :local varAddrFields {\
            ($varPrefixFields->0) ;\
            ($varPrefixFields->1) ;\
            ($varPrefixFields->2) ;\
            ($varPrefixFields->3) ;\
            ($varEUI64Fields->0) ;\
            ($varEUI64Fields->1) ;\
            ($varEUI64Fields->2) ;\
            ($varEUI64Fields->3)\
        }
        :put "$varAddrFields"
        :put "$[:len $varAddrFields]"
        :return [$MakeIP6Address $varAddrFields]
    }

    :return $argAddr
}

# Return general attributes of an IPv6 address.
#
# $1 (ip6, str): IPv6 address
# [$2] (integer): subnet prefix length; defaults to 128
# 
# $1 (str, ip6-prefix): IPv6 address-prefix
#
# > :put [$ParseIP6AddressCommon 2001:db8::1/64]
# address=2001:db8::1;addressPrefix=2001:db8::/64;prefix=2001:db8::;prefixLength=64
:global ParseIP6AddressCommon do={
    :global MakeIP6PrefixMask

    :local varRawAddr [:toip6 $1]
    :if ([:typeof $varRawAddr] = "nil") do={
        :set varRawAddr [:tostr $1]
    }
    :if ([:typeof $varRawAddr] = "nil") do={ :error "\"$1\" is invalid IPv6 address" }

    :local varAddr
    :local varPrefix
    :local varPrefixLen
    :if ([:typeof $varRawAddr] = "ip6") do={
        :set varAddr $varRawAddr

        :if ([:typeof $2] != "nothing") do={
            :set varPrefixLen [:tonum $2]
        } else={
            :set varPrefixLen 128
        }

        :if ([:typeof $varPrefixLen] = "nil") do={ :error "\"$2\" is invalid subnet prefix length" }
    } else={
        :local varDelimIdx [:find $varRawAddr "/"]

        :if ([:typeof $varDelimIdx] != "nil") do={
            :set varAddr [:toip6 [:pick $varRawAddr 0 $varDelimIdx]]
            :set varPrefixLen [:tonum [:pick $varRawAddr ($varDelimIdx + 1) [:len $varRawAddr]]]
        } else={
            :set varAddr [:toip6 $varRawAddr]
            :set varPrefixLen 128
        }

        :if ([:typeof $varAddr] = "nil") do={ :error "\"$1\" is invalid IPv6 address" }
        :if ([:typeof $varPrefixLen] = "nil") do={ :error "\"$1\" is invalid IPv6 address" }
    }

    :local varPrefixMask [$MakeIP6PrefixMask $varPrefixLen]
    :local varPrefix ($varAddr & $varPrefixMask)
    :local varAddrPrefix [[:parse ":return $varAddr/$varPrefixLen"]]

    :return {"address"=$varAddr ; "addressPrefix"=$varAddrPrefix ; "prefix"=$varPrefix ; "prefixLength"=$varPrefixLen}
}

# Return detailed attributes of an IPv6 address with respect to its type.
#
# $1 (array): An array of common IPv6 attributes
#
# > :put [$ParseIP6AddressDetail [$ParseIP6AddressCommon 2001:db8::1/64]]
# fields=8193;3512;0;0;0;0;0;1;globalID=2001:db8::;interfaceID=::1;subnetID=::;subtype=gua;type=unicast
:global ParseIP6AddressDetail do={
    :global MakeIP6AddressFields
    :global MakeIP6PrefixMask
    :global MakeIP6SuffixMask
    :global MakeIP6Address

    :local argAddr ($1->"address")
    :local varFields [$MakeIP6AddressFields $argAddr]

    :if ($argAddr = ::) do={ :return {"type"="unspecified" ; "fields"=$varFields} }
    :if ($argAddr = ::1) do={ :return {"type"="loopback" ; "fields"=$varFields} }
    :if ($argAddr in fe80::/10) do={ :return {"type"="link-local" ; "fields"=$varFields} }

    :if (($argAddr in ::/96) or ($argAddr in ::ffff:0:0/96)) do={
        :local varIP4 (\
            ((($varFields->6) & 0xff00) >> 16) . "." .\
            (($varFields->6) & 255) . "." .\
            ((($varFields->7) & 0xff00) >> 16) . "." .\
            (($varFields->7) & 0x00ff)\
        )
        :local varDetail {"fields"=$varFields ; "ip4"=$varIP4}

        :if (($varFields->5) = 0xffff) do={
            :set varDetail ($varDetail , {"type"="ip4-mapped"})
        } else={
            :set varDetail ($varDetail , {"type"="ip4-compatible"})
        }

        :return $varDetail
    }

    :if ($argAddr in ff00::/8) do={
        :local varFlags ((($varFields->0) & 0x00f0) >> 4)
        :local varScope (($varFields->0) & 0x000f)
        :local varDetail {"type"="multicast" ; "fields"=$varFields ; "flags"=$varFlags}

        :if (($varFlags & 3) = 3) do={
            # 0?11 - RFC3306
            :local varPrefixLen (($varFields->1) & 0x00ff)
            :local varPrefixFields {($varFields->2) ; ($varFields->3) ; ($varFields->4) ; ($varFields->5) ; 0 ; 0 ; 0; 0 }
            :local varPrefixMask [$MakeIP6PrefixMask $varPrefixLen]
            :local varPrefix ([$MakeIP6Address $varPrefixFields] & $varPrefixMask)
            :local varGroupID (($varFields->6 << 16) | $varFields->7)
            :set varDetail ($varDetail , {"subnetPrefix"=$varPrefix ; "subnetPrefixLength"=$varPrefixLen ; "groupID"=$varGroupID})

            :if ($varFlags & 4) do={
                # 0111 - RFC3956
                :local varRIIDRaw ((($varFields->1) & 0x0f00) >> 8)
                :local varRIIDFields {0 ; 0 ; 0 ; 0 ; 0 ; 0 ; 0 ; $varRIIDRaw}
                :local varRIID ($varPrefix | [$MakeIP6Address $varRIIDFields])
                :set varDetail ($varDetail , {"RIID"=$varRIID})
            }

            :if ($varPrefixLen = 0) do={
                :set varDetail ($varDetail , {"SSM"=yes})
            } else={
                :set varDetail ($varDetail , {"SSM"=no})
            }
        } else={
            :local varGroupID ($argAddr & [$MakeIP6SuffixMask 112])
            :set varDetail ($varDetail , {"groupID"=$varGroupID})
        }

        :return $varDetail
    }

    :local subtype
    :local globalID
    :local subnetID ::
    :local interfaceID ($argAddr & [$MakeIP6SuffixMask 64])
    :if ($argAddr in fc00::/7) do={
        # RFC4193
        :set subtype "ula"

        :local globalIDFields {(($varFields->0) & 0x00ff) ; ($varFields->1) ; ($varFields->2) ; 0 ; 0 ; 0 ; 0 ; 0}
        :set globalID [$MakeIP6Address $globalIDFields]

        :local subnetIDFields {0 ; 0 ; 0 ; ($varFields->3) ; 0 ; 0 ; 0 ; 0}
        :set subnetID [$MakeIP6Address $subnetIDFields]
    } else={
        #RFC3587
        :set subtype "gua"

        :local globalIDLen ($1->"prefixLength")
        :set globalID ($1->"prefix")

        :local subnetIDLen (64 - $globalIDLen)
        :if ($subnetIDLen > 0) do={
            :set subnetID ($varAddr & (~([$MakeIP6PrefixMask $globalIDLen])) & (~([$MakeIP6SuffixMask 64])))
        }
    }
    
    :return {"type"="unicast" ; "subtype"=$subtype ; "fields"=$varFields ; "globalID"=$globalID ; "subnetID"=$subnetID ; "interfaceID"=$interfaceID}
}

# See usage
:global ParseIP6Address do={
    :global ParseIP6AddressCommon
    :global ParseIP6AddressDetail

    :local varCommon [$ParseIP6AddressCommon $1 $2]

    :if ([:typeof $detail] != "nothing") do={
        :if ([[:parse "[:tobool $detail]"]]) do={
            :local varDetail [$ParseIP6AddressDetail $varCommon]
            :set varCommon ($varCommon , {"detail"=$varDetail})
        } 
    }

    :return $varCommon
}
