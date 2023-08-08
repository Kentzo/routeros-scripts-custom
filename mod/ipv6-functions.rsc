#!rsc by RouterOS

:global GlobalFunctionsReady;
:while ($GlobalFunctionsReady != true) do={ :delay 500ms; }

# Run command with arguments specified as an array.
#
# $1 (str): Full command name to run
# $2 (array): An array of command arguments
#
# Array of arguments may contain key-values which will be added as $key=$value
# or just values that will be added as is. Order of addition follows enumeration.
#
# > $RunCommandFromArray /ipv6/firewall/raw/print ({"detail", "where", "src-address-list"="blacklist"})
# /ipv6/firewall/raw/print detail where src-address-list=blacklist
#
:global RunCommandFromArray do={
    :global LogPrintExit2

    :local varCommand [:tostr $1]
    :foreach k,v in=$2 do={
        :if ([:typeof $k] = "num") do={
            :set varCommand ($varCommand . " $v")
        } else={
            :set varCommand ($varCommand . " $k=$v")
        }
    }
    :local varResult
    :do {
        $LogPrintExit2 debug $0 ("> $varCommand") false
        :set varResult [[:parse $varCommand]]
        $LogPrintExit2 debug $0 ("  $varResult") false
    } on-error={
        $LogPrintExit2 error $0 ("`$varCommand` failed") true
    }
    :return $varResult
}

# Update objects in place if they already exist; otherwise add them.
#
# $1 (str): Full path where find, add and set command will be run
# $2 (array): Search criteria
# $3 (array): Add/set properties
#:pare
# > $SetIfExistsElseAdd /ipv6/firewall/raw ({"comment~\"blocklist\""}) ({chain="prerouting";action="drop";comment="\"blocklist\""})
#
:global SetIfExistsElseAdd do={
    :local varExisting [$RunCommandFromArray ("$1/find") $2]
    :if ([:len $varExisting]) do={
        $RunCommandFromArray ("$1/set") ($3 , {numbers=$varExisting})
    } else={
        $RunCommandFromArray ("$1/add") $3
    }
}

# Same as SetIfExistsElseAdd but objects are only updated if they fail equality check.
#
# This is useful to avoid side effects of set, such as address re-allocation
# when setting /ipv6/address. It's costlier to run, avoid unless necessary.
#
# $1 (str): Full path where print, add and set commands will be run
# $2 (array): Search criteria
# $3 (array): Equality criteria, compared against `print as-value`
# $4 (array): Add/set properties
#
:global SetIfExistsElseAddUnlessEqual do={
    :local varExisting ([$RunCommandFromArray ("$1/print as-value where") $2]->0)
    :if ($varExisting) do={
        :foreach k,v in=$3 do={
            :if ([:typeof $k] = "num") do={
                $LogPrintExit2 error $0 ("equality criteria cannot have non-key elements") true
            }
            :local left ($varExisting->$k)
            :local right $v
            :if ($left != $right) do={
                $LogPrintExit2 debug $0 ("\"$k\": $left != $right") false
                $RunCommandFromArray ("$1/set") ($4 , {numbers=($varExisting->".id")})

                :local varNil
                :return $varNil
            }
        }
    } else={
        $RunCommandFromArray ("$1/add") $4
    }
}

# Wait for an /ipv6/address record with prefix $2 to appear on interface $1,
# optionally matched by the comment regex $3.
#
# $1 (str): Interface name to monitor
# $2 (ip6-prefix, str): IPv6 address-prefix the address must belong to
# [$3] (str): Regex that must match the comment of the /ipv6/address record
#
# > $WaitIP6Address loopback 2001:db8::/48
#
:global WaitIP6Address do={
    :local varAddress
    /ipv6/address {
        :retry command={
            :set varAddress [get value-name=address [find interface=$1 (address in $2) comment~"$3"]]
        } delay=1 max=5
    }
    :return $varAddress
}

# Assert that a given variable named $1 has non-empty value $2
# $1 (str): Name of the variable for logging
# $2: Value for checking
#
# > $AssertNotEmpty argLoopbackInt $argLoopbackInt
#
:global AssertNotEmpty do={
    :global LogPrintExit2

    :if ([:len $2] = 0) do={
        $LogPrintExit2 $0 error ("$1 cannot be empty") true
    }
}
