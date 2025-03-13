#!rsc by RouterOS

# Set up NPTv6.
#
# GUA prefix is reserved by allocating a network from $argWanPool
# on $argLoopbackInt. Once GUA network is available, its address-prefix
# is used to set up mangling rules to perform network prefix translation
# with addresses from $argUlaPool.
#
# Since mangling is performed after connection tracking, all mangled packets
# continue processing with connection-state=invalid. Thus raw rules are added
# to mark these packets for notrack. Adjust your filter rules accordingly.
#
# Optional arg*Extra can be used to further narrow matching criteria.
# E.g. to perform translation only when the packet is routed through WAN:
#
#   :global argSnptMangleExtra {"out-interface-list"="WAN"}
#
#
# Arguments:
#   argLoopbackInt (str): name of the loopback interface
#   argWanPool (str): name of the WAN pool
#   argUlaPool (str): name of the ULA pool
#   argManagedID (str): regex-escaped unique ID of the managed objects
#   [argSnptMangleExtra] (array): Optional extra properties for the SNPT mangle rule
#   [argDnptMangleExtra] (array): Optional extra properties for the DNPT mangle rule
#   [argSnptRawExtra] (array): Optional extra properties for the SNPT raw rule
#   [argDnptRawExtra] (array): Optional extra properties for the DNPT raw rule
#
#
# Affects:
#   /ipv6/address
#   /ipv6/firewall/mangle
#   /ipv6/firewall/raw
#
#
# Requirements:
#   - mod/kentzo-functions

:global GlobalFunctionsReady;
:while ($GlobalFunctionsReady != true) do={ :delay 500ms; }


:local SetupRules do={
    :global argLoopbackInt
    :global argWanPool
    :global argManagedID
    :global argSnptMangleExtra
    :global argDnptMangleExtra
    :global argSnptRawExtra
    :global argDnptRawExtra

    :global WaitIP6Address
    :global SetIfExistsElseAdd
    :global SetIfExistsElseAddUnlessEqual

    $SetIfExistsElseAddUnlessEqual /ipv6/address\
        ({"comment~\"$argManagedID\\\$\""})\
        ({\
            interface="$argLoopbackInt";\
            advertise=false;\
            "from-pool"="$argWanPool"\
        })\
        ({\
            interface=$argLoopbackInt;\
            advertise="no";\
            "from-pool"=$argWanPool;\
            comment="\"Managed: NPTv6 / $argManagedID\""\
        })
    :local varGuaPrefix [$WaitIP6Address $argLoopbackInt $2 ("$argManagedID\$")]

    $SetIfExistsElseAdd /ipv6/firewall/mangle\
        ({"comment~\"snpt-$argManagedID\\\$\""})\
        ($argSnptMangleExtra , {\
            chain="postrouting";\
            action="snpt";\
            "src-address"=$1;\
            "src-prefix"=$1;\
            "dst-prefix"=$varGuaPrefix;\
            comment="\"Managed: NPTv6 / snpt-$argManagedID\""\
        })

    $SetIfExistsElseAdd /ipv6/firewall/mangle\
        ({"comment~\"dnpt-$argManagedID\\\$\""})\
        ($argDnptMangleExtra , {\
            chain="prerouting";\
            action="dnpt";\
            "dst-address"=$varGuaPrefix;\
            "src-prefix"=$varGuaPrefix;\
            "dst-prefix"=$1;\
            comment="\"Managed: NPTv6 / dnpt-$argManagedID\""\
        })

    $SetIfExistsElseAdd /ipv6/firewall/raw\
        ({"comment~\"snpt-$argManagedID\\\$\""})\
        ($argSnptRawExtra , {\
            chain="prerouting";\
            action="notrack";\
            "src-address"=$1;\
            comment="\"Managed: NPTv6 / snpt-$argManagedID\""\
        })

    $SetIfExistsElseAdd /ipv6/firewall/raw\
        ({"comment~\"dnpt-$argManagedID\\\$\""})\
        ($argDnptRawExtra , {\
            chain="prerouting";\
            action="notrack";\
            "dst-address"=$varGuaPrefix;\
            comment="\"Managed: NPTv6 / dnpt-$argManagedID\""\
        })
}

:local TearDown do={
    :global argManagedID
    /ipv6/address/remove [find comment~"$argManagedID\$"]
    /ipv6/firewall/mangle/remove [find comment~"$argManagedID\$"]
    /ipv6/firewall/raw/remove [find comment~"$argManagedID\$"]
}

:global LogPrint
:global AssertNotEmpty

:global argLoopbackInt
:global argWanPool
:global argUlaPool
:global argManagedID

$AssertNotEmpty argLoopbackInt
$AssertNotEmpty argWanPool
$AssertNotEmpty argUlaPool
$AssertNotEmpty argManagedID


/ipv6/pool
:local varWanPrefix [get value-name=prefix $argWanPool]
:local varUlaPrefix [get value-name=prefix $argUlaPool]

:do {
    $SetupRules $varUlaPrefix $varWanPrefix
    $LogPrint info $0 ("Add NPT: $varUlaPrefix <-> $varWanPrefix")
} on-error={
    $LogPrint warning $0 ("Failed to update NPTv6, retrying from scratch")
    :do {
        $TearDown
        $SetupRules $varUlaPrefix $varWanPrefix
    } on-error={
        $TearDown
        $LogPrint error $0 ("Failed to set up NPTv6")
        :error "fatal error in ipv6-npt.rsc"
    }
}
