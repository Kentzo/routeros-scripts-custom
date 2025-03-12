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

# Structure an IPv4 network.
#
# $1 (ip-prefix, str): IPv4 network
#
# > :put [$StructureIPNetwork 192.0.2.1/8]
# address=192.0.0.0;length=8;mask=255.0.0.0
#
:global StructureIPNetwork do={
    :global MakeIPPrefixMask

    :local argNetwork [:tostr $1]
    :local varDelimIdx [:find $1 "/" -1]

    :local varAddr [:toip [:pick $argNetwork -1 $varDelimIdx]]
    :if ([:typeof $varAddr] != "ip") do={ :error "\"$1\" is invalid IPv4 network"}

    :local varNetworkLen [:tonum [:pick $argNetwork ($varDelimIdx + 1) [:len $argNetwork]]]
    :if (($varNetworkLen < 0) or ($varNetworkLen > 32) or ($varNetworkLen % 4) != 0) do={ :error "$1 is invalid IPv4 network" }

    :local varNetworkMask [$MakeIPPrefixMask $varNetworkLen]

    :set varAddr ($varAddr & $varNetworkMask)

    :return {"address"=$varAddr;"length"=$varNetworkLen;"mask"=$varNetworkMask}
}

# Make an RFC1035 domain from an IPv4 address.
#
# $1 (ip4, str): IPv4 address
#
# > :put [$MakeIPDomain 192.0.2.1]
# 1.2.0.192.in-addr.arpa.
#
:global MakeIPDomain do={
    :global MakeIPFieldsFromAddress

    :local varFields [$MakeIPFieldsFromAddress $1]
    :return "$($varFields->3).$($varFields->2).$($varFields->1).$($varFields->0).in-addr.arpa"
}

# Make an RFC1034 / RFC2317 domain from an IPv4 network.
#
# $1 (ip-prefix, str, array): IPv4 address
# [rfc2317] (bool): Whether to follow RFC2317 recommendation for networks on non-octet boundaries
#
# > :put [$MakeIPNetworkDomain 192.0.2.0/24]
# 2.0.192.in-addr.arpa.
# > :put [$MakeIPNetworkDomain 192.0.2.0/25]
# 2.0.192.in-addr.arpa.
# > :put [$MakeIPNetworkDomain 192.0.2.0/25 rfc2317=yes]
# 0/25.2.0.192.in-addr.arpa.
#
:global MakeIPNetworkDomain do={
    :global MakeIPPrefixMask
    :global MakeIPFieldsFromAddress
    :global StructureIPNetwork

    :local argNetwork
    :if ([:typeof $1] = "array") do={
        :set argNetwork $1
    } else={
        :set argNetwork [$StructureIPNetwork $1]
    }
    :local varAddr ($argNetwork->"address")
    :local varNetworkLen ($argNetwork->"length")

    :local varFields [$MakeIPFieldsFromAddress $varAddr]
    :local varDomain "in-addr.arpa"

    :for fieldIdx from=0 to=($varNetworkLen / 8 - 1) step=1 do={
        :set varDomain "$($varFields->$fieldIdx).$varDomain"
    }

    :if ((($varNetworkLen % 8) != 0) and ([:typeof $rfc2317] != "nothing")) do={
        :if ([[:parse "[:tobool $rfc2317]"]]) do={
            :set varDomain "$($varFields->($varNetworkLen / 8))/$varNetworkLen.$varDomain"
        }
    }

    :return $varDomain
}
