#!rsc by RouterOS

# Make an IPv4 prefix mask of a given length.
#
# $1 (integer): prefix length
#
# > :put [$MakeIPPrefixMask 24]
# 255.255.255.0
#
:global MakeIPPrefixMask do={
    :if (($1 < 0) or ($1 > 32)) do={ :error "$1 is invalid IPv4 mask length" }
    :return ((255.255.255.255 >> (32 - $1)) << (32 - $1))
}

# Make an IPv4 suffix mask of a given length.
#
# $1 (integer): prefix length
#
# > :put [$MakeIPSuffixMask 24]
# 0.255.255.255
#
:global MakeIPSuffixMask do={
    :if (($1 < 0) or ($1 > 32)) do={ :error "$1 is invalid IPv4 mask length" }
    :return ((255.255.255.255 << (32 - $1)) >> (32 - $1))
}

# Make an array of four 8bit integers that represent IPv4 address,
# one integer per field.
#
# $1 (ip, str): IPv4 address
#
# > :put [$MakeIPFieldsFromAddress 192.0.2.1]
# 192;0;2;1
#
:global MakeIPFieldsFromAddress do={
    :local argAddr [:toip $1]
    :if ([:typeof $argAddr] != "ip") do={ :error "\"$1\" is invalid IPv4 address"}
    :set argAddr [:tostr $argAddr]

    :local varLastDelimIdx -1

    :local varDelimIdx [:find $argAddr "." $varLastDelimIdx]
    :local varField1 [:tonum [:pick $argAddr ($varLastDelimIdx + 1) $varDelimIdx]]
    :set varLastDelimIdx $varDelimIdx

    :set varDelimIdx [:find $argAddr "." $varLastDelimIdx]
    :local varField2 [:tonum [:pick $argAddr ($varLastDelimIdx + 1) $varDelimIdx]]
    :set varLastDelimIdx $varDelimIdx

    :set varDelimIdx [:find $argAddr "." $varLastDelimIdx]
    :local varField3 [:tonum [:pick $argAddr ($varLastDelimIdx + 1) $varDelimIdx]]
    :set varLastDelimIdx $varDelimIdx

    :local varField4 [:tonum [:pick $argAddr ($varLastDelimIdx + 1) [:len $argAddr]]]

    :return ({$varField1 ; $varField2 ; $varField3 ; $varField4})
}

# Make an IPv4 address from an array of four 8bit integers.
#
# $1 (array): IPv4 address fields
#
# > :put [$MakeIPAddressFromFields ({192;0;2;1})]
# 192.0.2.1
#
:global MakeIPAddressFromFields do={
    :return [:toip "$($1->0).$($1->1).$($1->2).$($1->3)"]
}

# Expand an array of four 8bit integers into a IPv4 address string with all decimals present.
#
# $1 (array): IPv4 address fields
#
# > :put [$ExpandIPAddressFromFields ({192;0;2;1})]
# 192.000.002.001
#
:global ExpandIPAddressFromFields do={
    :local varAddr ""

    :for fieldIdx from=0 to=3 step=1 do={
        :local varFieldNum ($1->$fieldIdx)
        :if ($varFieldNum < 10) do={
            :set varAddr ($varAddr . "00$varFieldNum")
        } else={
            :if ($varFieldNum < 100) do={
                :set varAddr ("$varAddr" . "0$varFieldNum")
            } else={
                :set varAddr ("$varAddr" . "$varFieldNum")
            }
        }

        :if ($fieldIdx != 3) do={ :set varAddr ($varAddr . ".") }
    }

    :return $varAddr
}

# Expand IPv4 address into a string with all decimals present.
#
# $1 (ip, str): IPv4 address
#
# > :put [$ExpandIPAddress 192.0.2.1]
# 192.000.002.001
#
:global ExpandIPAddress do={
    :global MakeIPFieldsFromAddress
    :global ExpandIPAddressFromFields
    :return [$ExpandIPAddressFromFields [$MakeIPFieldsFromAddress $1]]
}

# Make a structure of common IPv4 atributes.
#
# - $1 (ip, str): IPv4 address
#   [$2] (integer): subnet prefix length; defaults to 32
#
# - $1 (str, ip-prefix): IPv4 address-prefix
#
# Returns:
#  address (ip): IPv4 address of the input
#  addressPrefix (ip-prefix): IPv4 address-prefix of the input
#  prefix (ip): Prefix of the input
#  prefixMask (ip): Netmask of the input
#  prefixLength (integer): Prefix length of the input
#
# > :put [$StructureIPAddressCommon 192.0.2.1/16]
# address=192.0.2.1;addressPrefix=192.0.0.0/16;prefix=192.0.0.0;prefixLength=16;prefixMask=255.255.0.0
#
:global StructureIPAddressCommon do={
    :global MakeIPPrefixMask

    :local varRawAddr [:toip $1]
    :if ([:typeof $varRawAddr] = "nil") do={ :set varRawAddr [:tostr $1] }
    :if ([:typeof $varRawAddr] = "nil") do={ :error "\"$1\" is invalid IPv4 address" }

    :local varAddr
    :local varPrefix
    :local varPrefixLen
    :if ([:typeof $varRawAddr] = "ip") do={
        :set varAddr $varRawAddr

        :if ([:len $2] != 0) do={
            :set varPrefixLen [:tonum $2]
        } else={
            :set varPrefixLen 32
        }

        :if ([:typeof $varPrefixLen] = "nil") do={ :error "\"$2\" is invalid subnet prefix length" }
    } else={
        :local varDelimIdx [:find $varRawAddr "/"]

        :if ([:typeof $varDelimIdx] != "nil") do={
            :set varAddr [:toip [:pick $varRawAddr 0 $varDelimIdx]]
            :set varPrefixLen [:tonum [:pick $varRawAddr ($varDelimIdx + 1) [:len $varRawAddr]]]
        } else={
            :set varAddr [:toip $varRawAddr]
            :set varPrefixLen 32
        }

        :if ([:typeof $varAddr] = "nil") do={ :error "\"$1\" is invalid IPv4 address" }
        :if ([:typeof $varPrefixLen] = "nil") do={ :error "\"$1\" is invalid IPv4 address" }
    }

    :local varPrefixMask [$MakeIPPrefixMask $varPrefixLen]
    :local varPrefix ($varAddr & $varPrefixMask)
    :local varAddrPrefix [[:parse ":return $varPrefix/$varPrefixLen"]]

    :return {"address"=$varAddr ; "addressPrefix"=$varAddrPrefix ; "prefix"=$varPrefix ; "prefixLength"=$varPrefixLen ; "prefixMask"=$varPrefixMask}
}

# Make an RFC1035 domain from an IPv4 address.
#
# - $1 (ip, str): IPv4 address
#
# - $1 (ip-prefix, str): IPv4 network
#   [rfc2317] (bool): Whether to follow RFC2317 recommendation for networks on non-octet boundaries
#
# - $1 (array): IPv4 address structure
#   [rfc2317] (bool): Whether to follow RFC2317 recommendation for networks on non-octet boundaries
#
# > :put [$MakeIPDomain 192.0.2.1]
# 1.2.0.192.in-addr.arpa.
# > :put [$MakeIPDomain 192.0.2.0/24]
# 2.0.192.in-addr.arpa.
# > :put [$MakeIPDomain 192.0.2.0/25]
# 2.0.192.in-addr.arpa.
# > :put [$MakeIPDomain 192.0.2.0/25 rfc2317=yes]
# 0/25.2.0.192.in-addr.arpa.
#
:global MakeIPDomain do={
    :global MakeIPPrefixMask
    :global MakeIPFieldsFromAddress
    :global StructureIPAddressCommon

    :local argNetworkStruct
    :if ([:typeof $1] = "array") do={
        :set argNetworkStruct $1
    } else={
        :set argNetworkStruct [$StructureIPAddressCommon $1]
    }
    :local varAddr ($argNetworkStruct->"prefix")
    :local varNetworkLen ($argNetworkStruct->"prefixLength")

    :local varFields [$MakeIPFieldsFromAddress $varAddr]
    :local varDomain "in-addr.arpa."

    :for fieldIdx from=0 to=($varNetworkLen / 8 - 1) step=1 do={
        :set varDomain "$($varFields->$fieldIdx).$varDomain"
    }

    :if ((($varNetworkLen % 8) != 0) and ([:len $rfc2317] != 0)) do={
        :if ([[:parse "[:tobool $rfc2317]"]]) do={
            :set varDomain "$($varFields->($varNetworkLen / 8))/$varNetworkLen.$varDomain"
        }
    }

    :return $varDomain
}

# Deduplicate, coalesce and sort IPv4 addresses and prefixes.
#
# - $1 (array): An array of IPv4 addresses and/or prefixes
#   [structure] (bool): Whether to structure the output; defaults to false
#
# - $1 (array): An array of IPv4 address structures
#
# > :put [$DeduplicateIPAddresses ({192.0.2.0/28;192.0.2.32/28;192.0.2.40/29;192.0.2.0/28})]
# 192.0.2.0/28;192.0.2.32/28
#
:global DeduplicateIPAddresses do={
    :global ExpandIPAddress
    :global GetArrayValues
    :global StructureIPAddressCommon

    # Dictionary will deduplicate and sort.
    :local varDeduplicatedPrefixes ({})
    :foreach prefix in=$1 do={
        :local varPrefixStruct
        :if ([:typeof $prefix] = "array") do={
            :set varPrefixStruct $prefix
        } else={
            :set varPrefixStruct [$StructureIPAddressCommon $prefix]
        }

        :local varSortKey [$ExpandIPAddress ($varPrefixStruct->"prefix")]

        # Maintain shorter prefix.
        :if ($varDeduplicatedPrefixes->$varSortKey != nil) do={
            :if ($varPrefixStruct->"prefixLength" < $varDeduplicatedPrefixes->$varSortKey->"prefixLength") do={
                :set ($varDeduplicatedPrefixes->$varSortKey) $varPrefixStruct
            }
        } else={
            :set ($varDeduplicatedPrefixes->$varSortKey) $varPrefixStruct
        }
    }

    :set varDeduplicatedPrefixes [$GetArrayValues $varDeduplicatedPrefixes]

    :local varCoalescedPrefixes ({$varDeduplicatedPrefixes->0})
    :local varParentIdx 0
    :local varCurIdx 1
    :while ($varCurIdx < [:len $varDeduplicatedPrefixes]) do={
        :if (($varDeduplicatedPrefixes->$varCurIdx->"prefix" in $varDeduplicatedPrefixes->$varParentIdx->"addressPrefix") = false) do={
            :set varCoalescedPrefixes ($varCoalescedPrefixes , {$varDeduplicatedPrefixes->$varCurIdx})
            :set varParentIdx $varCurIdx
        }
        :set varCurIdx ($varCurIdx + 1)
    }

    :if ([:len $structure] != 0) do={
        :if ([[:parse "[:tobool $structure]"]]) do={
            :return $varCoalescedPrefixes
        }
    }

    :local varTmp ({})
    :foreach prefixStruct in=$varCoalescedPrefixes do={ :set varTmp ($varTmp , $prefixStruct->"addressPrefix") }
    :return $varTmp
}
