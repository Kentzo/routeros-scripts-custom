#!rsc by RouterOS

# Make an IPv6 prefix mask of a given length.
#
# $1 (integer): prefix length
#
# > :put [$MakeIP6PrefixMask 64]
# ffff:ffff:ffff:ffff::
#
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

# Make an IPv6 suffix mask of a given length.
#
# $1 (integer): prefix length
#
# > :put [$MakeIP6PrefixMask 64]
# ::ffff:ffff:ffff:ffff
#
:global MakeIP6SuffixMask do={
    :global MakeIP6PrefixMask

    :if (($1 < 0) or ($1 > 128)) do={ :error "$1 is invalid IPv6 mask length" }
    :return (~[$MakeIP6PrefixMask (128 - $1)])
}

# Make an array of eight 16bit integers that represent IPv6 address,
# one integer per field.
#
# $1 (ip6, str): IPv6 address
#
# > :put [$MakeIP6FieldsFromAddress 2001:db8::1]
# 8193;3512;0;0;0;0;0;1
#
:global MakeIP6FieldsFromAddress do={
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

# Make an IPv6 address from an array of eight 16bit integers.
#
# $1 (array): IPv6 address fields
#
# > :put [$MakeIP6FieldsFromAddress ({8193;3512;0;0;0;0;0;1})]
# 2001:db8::1
#
:global MakeIP6AddressFromFields do={
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

# Make an IPv6 address from a MAC via the EUI-64 method.
#
# $1 (ip6, str): IPv6 prefix
# $2 (str): MAC
#
# > :put [$MakeIP6AddressFromEUI64 2001:db8:: "00:00:5E:00:53:01"]
# 2001:db8::200:5eff:fe00:5301
#
:global MakeIP6AddressFromEUI64 do={
    :local argAddr [:toip6 $1]
    :if ([:typeof $argAddr] != "ip6") do={ :error "\"$1\" is invalid IPv6 address"}

    :local argMAC $2
    :if (!([:typeof $argMAC] = "str") or !([:len $argMAC] = 17)) do={ :error "\"$2\" is invalid MAC" }

    :local varPrefixFields [$MakeIP6FieldsFromAddress $1]
    :local varMACFields {\
        [:tonum "0x$[:pick $argMAC 0 2]"] ;\
        [:tonum "0x$[:pick $argMAC 3 5]"] ;\
        [:tonum "0x$[:pick $argMAC 6 8]"] ;\
        [:tonum "0x$[:pick $argMAC 9 11]"] ;\
        [:tonum "0x$[:pick $argMAC 12 14]"] ;\
        [:tonum "0x$[:pick $argMAC 15 17]"]\
    }
    :local varEUI64Fields {\
        (((($varMACFields->0) << 8) | ($varMACFields->1)) ^ 0x0200) ;\
        ((($varMACFields->2) << 8) | 0x00ff) ;\
        (0xfe00 | ($varMACFields->3)) ;\
        ((($varMACFields->4) << 8) | ($varMACFields->5))\
    }
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
    :return [$MakeIP6AddressFromFields $varAddrFields]
}

# Make an IPv6 address by translating prefix of $1 from $2 to $3.
#
# $1 (ip6, str):
# $2 (ip6-prefix, str):
# $3 (ip6-prefix, str):
#
# > $MakeIP6AddressFromNPT fd01:203:405:1::1234 fd01:203:405::/48 2001:db8:1::/48
# 2001:db8:1:d550::1234
# > $MakeIP6AddressFromNPT 2001:db8:1:d550::1234 2001:db8:1::/48 fd01:203:405::/48
# fd01:203:405:1::1234
#
:global MakeIP6AddressFromNPT do={
    :global MakeIP6AddressFromFields
    :global StructureIP6Address

    :local varAddr [$StructureIP6Address $1 detail=yes]
    :if (!(($varAddr->"address") in $2)) do={ :error "$2 is invalid, must include $1" }
    :local varAddrFields ($varAddr->"detail"->"fields")

    :local varSrcPrefix [$StructureIP6Address $2]
    :local varPrefixLen ($varSrcPrefix->"prefixLength")
    :set varSrcPrefix [$StructureIP6Address ($varSrcPrefix->"prefix") detail=yes]
    :local varSrcFields ($varSrcPrefix->"detail"->"fields")

    :local varDstPrefix [$StructureIP6Address $3]
    :if ($varPrefixLen < ($varDstPrefix->"prefixLength")) do={ :set varPrefixLen ($varDstPrefix->"prefixLength") }
    :set varDstPrefix [$StructureIP6Address ($varDstPrefix->"prefix") detail=yes]
    :local varDstFields ($varDstPrefix->"detail"->"fields")

    :local MakeOneComplement do={ :return ($1 ^ 0xffff) }
    :local FitOneComplement do={ :return (($1 & 0xffff) + ($1 >> 16)) }
    :local MakeChecksum do={ :return (($1->0) + ($1->1) + ($1->2) + ($1->3) + ($1->4) + ($1->5) + ($1->6) + ($1->7)) }

    :local varSrcChecksum [$MakeOneComplement [$FitOneComplement [$MakeChecksum $varSrcFields]]]
    :local varDstChecksum [$MakeOneComplement [$FitOneComplement [$MakeChecksum $varDstFields]]]
    :local varAdjustment [$FitOneComplement ($varDstChecksum + [$MakeOneComplement $varSrcChecksum])]

    :local varNPTAddrFields ($varDstPrefix->"address" | (($varAddr->"address") & [$MakeIP6SuffixMask (128 - $varPrefixLen)]))
    :set varNPTAddrFields ([$StructureIP6Address $varNPTAddrFields detail=yes]->"detail"->"fields")

    :local varAdjustedNPTAddrFields
    :if ($varPrefixLen <= 48) do={
        :set varAdjustedNPTAddrFields ({\
            ($varNPTAddrFields->0) ;\
            ($varNPTAddrFields->1) ;\
            ($varNPTAddrFields->2) ;\
            [$FitOneComplement (($varNPTAddrFields->3) + $varAdjustment)] ;\
            ($varNPTAddrFields->4) ;\
            ($varNPTAddrFields->5) ;\
            ($varNPTAddrFields->6) ;\
            ($varNPTAddrFields->7)\
        })
    } else={
        :local varAdjustmentFieldIdx ((($varPrefixLen - 1) / 16) + 1)
        :while (($varNPTAddrFields->$varAdjustmentFieldIdx) = 0xffff) do={
            :set varAdjustmentFieldIdx ($varAdjustmentFieldIdx + 1)
        }
        :if ($varAdjustmentFieldIdx = 8) do={ :error "cannot find field to apply adjustment" }

        :set varAdjustedNPTAddrFields ({})
        :for fieldIdx from=0 to=7 do={
            :if ($fieldIdx = $varAdjustmentFieldIdx) do={
                :set varAdjustedNPTAddrFields ($varAdjustedNPTAddrFields , [$FitOneComplement (($varNPTAddrFields->$fieldIdx) + $varAdjustment)])
            } else={
                :set varAdjustedNPTAddrFields ($varAdjustedNPTAddrFields , $varNPTAddrFields->$fieldIdx)
            }
        }
    }

    :return [$MakeIP6AddressFromFields $varAdjustedNPTAddrFields]
}

# Make a structure of common IPv6 atributes.
#
# - $1 (ip6, str): IPv6 address
#   [$2] (integer): subnet prefix length; defaults to 128
# 
# - $1 (str, ip6-prefix): IPv6 address-prefix
#
# Returns:
#  address (ip6): IPv6 address of the input
#  addressPrefix (ip6-prefix): IPv6 address-prefix of the input
#  prefix (ip6): Prefix of the input
#  prefixLength (integer): Prefix length of the input
#
# > :put [$StructureIP6AddressCommon 2001:db8::1/64]
# address=2001:db8::1;addressPrefix=2001:db8::/64;prefix=2001:db8::;prefixLength=64
#
:global StructureIP6AddressCommon do={
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

# Make a structure of type-specific IPv6 atributes.
#
# $1 (array): A structure of common IPv6 attributes
#
# Returns:
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
#   flags (integer): Multicast flags
#   groupID (integer): Multicast group ID
#
# - type (str): "multicast"
#   fields (array): Address as an array of 8 integers
#   flags (integer): Multicast flags
#   subnetPrefix (ip6): Unicast base
#   subnetPrefixLength (integer): Length of the unicast base
#   groupID (integer): Multicast group ID
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
# > :put [$StructureIP6AddressDetail [$StructureIP6AddressCommon 2001:db8::1/64]]
# fields=8193;3512;0;0;0;0;0;1;globalID=2001:db8::;interfaceID=::1;subnetID=::;subtype=gua;type=unicast
#
:global StructureIP6AddressDetail do={
    :global MakeIP6FieldsFromAddress
    :global MakeIP6PrefixMask
    :global MakeIP6SuffixMask
    :global MakeIP6AddressFromFields

    :local argAddr ($1->"address")
    :local varFields [$MakeIP6FieldsFromAddress $argAddr]

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
            :local varPrefix ([$MakeIP6AddressFromFields $varPrefixFields] & $varPrefixMask)
            :local varGroupID (($varFields->6 << 16) | $varFields->7)
            :set varDetail ($varDetail , {"subnetPrefix"=$varPrefix ; "subnetPrefixLength"=$varPrefixLen ; "groupID"=$varGroupID})

            :if ($varFlags & 4) do={
                # 0111 - RFC3956
                :local varRIIDRaw ((($varFields->1) & 0x0f00) >> 8)
                :local varRIIDFields {0 ; 0 ; 0 ; 0 ; 0 ; 0 ; 0 ; $varRIIDRaw}
                :local varRIID ($varPrefix | [$MakeIP6AddressFromFields $varRIIDFields])
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
        :set globalID [$MakeIP6AddressFromFields $globalIDFields]

        :local subnetIDFields {0 ; 0 ; 0 ; ($varFields->3) ; 0 ; 0 ; 0 ; 0}
        :set subnetID [$MakeIP6AddressFromFields $subnetIDFields]
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

# Make a structure from an IPv6 address.
#
# - $1 (ip6, str): IPv6 address
#   $2 (integer): Prefix length
#   [detail] (bool): Whether to include details; defaults to false
#
# - $1 (ip6-prefix, str): IPv6 address-prefix
#   [detail] (bool): Whether to include details; defaults to false
#
:global StructureIP6Address do={
    :global StructureIP6AddressCommon
    :global StructureIP6AddressDetail

    :local varCommon [$StructureIP6AddressCommon $1 $2]

    :if ([:typeof $detail] != "nothing") do={
        :if ([[:parse "[:tobool $detail]"]]) do={
            :local varDetail [$StructureIP6AddressDetail $varCommon]
            :set varCommon ($varCommon , {"detail"=$varDetail})
        } 
    }

    :return $varCommon
}
