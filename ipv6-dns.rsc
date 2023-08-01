#!rsc by RouterOS
#
# Requirements:
#   - mod/ipv6-functions
#   - mod/ipv6-structured
#
# Usage:
#
# argWanPool: name of the WAN pool 
# argHosts: An array of {interface ; IID ; name} records
# argManagedID: regex-escaped unique ID of the managed objects
#
# For every host in $argHosts one /ipv6/firewall/address-list
# and one AAAA /ip/dns/static record will be added.
#

:global argWanPool
:global argHosts
:global argManagedID

:global GlobalFunctionsReady;
:while ($GlobalFunctionsReady != true) do={ :delay 500ms; }

:global WaitIP6Address
:global StructureIP6Address
:global LogPrintExit2

/ipv6/pool
:local varWanPrefix [get value-name=prefix $argWanPool]
:local varWanPrefixTTL [get value-name=expires-after $argWanPool]
:if ([:typeof $varWanPrefixTTL] = "nil") do={
    :set varWanPrefixTTL 1d00:00:00
} else={
    :set varWanPrefixTTL ($varWanPrefixTTL + 01:00:00)
}

:foreach varHost in=$argHosts do={
    :local varInt ($varHost->0)
    :local varIID ($varHost->1)
    :local varName ($varHost->2)

    :do {
        :local varPrefix ([$StructureIP6Address [$WaitIP6Address $varInt $varWanPrefix ""]]->"prefix")
        :local varAddr ($varPrefix | $varIID)

        /ipv6/firewall/address-list
        remove [find list=$varName comment~"$argManagedID\$"]
        :log info "Add $varName -> $varAddr address list, expires after $varWanPrefixTTL"
        add list=$varName address=$varAddr timeout=$varWanPrefixTTL comment="Managed: DNSv6 / $argManagedID"

        /ip/dns/static
        remove [find name=$varName comment~"$argManagedID\$"]
        :log info "Add $varName -> $varAddr dns, expires after $varWanPrefixTTL"
        add name=$varName address=$varAddr type=AAAA ttl=$varWanPrefixTTL comment="Managed: DNSv6 / $argManagedID"
    } on-error={
        $LogPrintExit2 error $0 ("No prefix from $varWanPrefix on $varInt") true
    }
}