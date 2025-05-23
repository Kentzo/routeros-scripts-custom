#!rsc by RouterOS

# Run command with arguments specified as an array.
#
# $1 (str): Full command name to run
# $2 (array): An array of command arguments
#
# Array of arguments may contain key-values which will be added as $key=$value
# or just values that will be added as is. Order of arguments follows array enumeration.
#
# > $RunCommandFromArray /ipv6/firewall/raw/print ({"detail", "where", "src-address-list"="blacklist"})
# /ipv6/firewall/raw/print detail where src-address-list=blacklist
#
:global RunCommandFromArray do={
    :global LogPrint

    :local varCommand [:tostr $1]
    :foreach k,v in=$2 do={
        :if ([:typeof $k] = "num") do={
            :set varCommand ($varCommand . " $[:tostr $v]")
        } else={
            :set varCommand ($varCommand . " $k=$[:tostr $v]")
        }
    }
    :local varResult
    :onerror varError in={
        $LogPrint debug ("$[:jobname]/$0") ("> $varCommand")
        :set varResult [[:parse $varCommand]]
        $LogPrint debug ("$[:jobname]/$0") ("  $[:tostr $varResult]")
    } do={
        :error ("`$varCommand` failed: $varError")
    }
    :return $varResult
}

# Update objects in place if they already exist; otherwise add them.
#
# $1 (str): Full path where find, add and set commands will be run
# $2 (array): Search criteria
# $3 (array): Add/set properties
#
# > $SetIfExistsElseAdd /ipv6/firewall/raw ({"comment~\"blocklist\""}) ({chain="prerouting";action="drop";comment="\"blocklist\""})
#
:global SetIfExistsElseAdd do={
    :global RunCommandFromArray

    :local varExisting ([$RunCommandFromArray ("$1/find") $2]->0)
    :if ($varExisting) do={
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
    :global LogPrint
    :global RunCommandFromArray

    :local varExisting ([$RunCommandFromArray ("$1/print") ({"as-value" ; "where"} , $2)]->0)
    :if ($varExisting) do={
        :foreach k,v in=$3 do={
            :if ([:typeof $k] = "num") do={
                :error ("equality criteria cannot have non-key elements")
            }
            :local left ($varExisting->$k)
            :local right $v
            :if ($left != $right) do={
                $LogPrint debug ("$[:jobname]/$0") ("\"$k\": $left != $right")
                $RunCommandFromArray ("$1/set") ($4 , {numbers=($varExisting->".id")})
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
    /ipv6/address {
        :retry command={
            :local varAddress [get value-name=address ([find interface=$1 (address in $2) comment~"$3"]->0)]
            $LogPrint debug ("$[:jobname]/$0") ("$varAddress from $2 is available on $1")
            :return $varAddress
        } on-error={
            :local varWrongAddresses
            :foreach varAddress in=[print as-value proplist=address where interface=$1 comment~"$3"] do={
                :set varWrongAddresses ($varWrongAddresses . " $($varAddress->address)")
            }
            :error ("expected an address from $2 on $1, got ($varWrongAddresses) instead")
        } delay=1 max=5
    }
}

# Assert that a given global variable named $1 has a non-empty value.
#
# $1 (str): Name of the variable
#
# > $AssertNotEmpty argLoopbackInt
#
:global AssertNotEmpty do={
    :if ([[:parse ":global $1; :return ([:len \$$1] > 0)"]]) do={
        :return true
    }

    :error ("\$$1 cannot be empty")
}

# Assert that at least one of given global variables has a non-empty value.
#
# $1 (array): An array of variable names.
#
# > $AssertAnyOfNotEmpty ({"argNSIPAddress" ; "argNSIP6Address"})
#
:global AssertAnyOfNotEmpty do={
    :global LogPrint

    :foreach name in=$1 do={
        :if ([[:parse "global $name; :return ([:len \$$name] > 0)"]]) do={
            :return true
        }
    }

    :error ("at least one of {$[:tostr $1]} cannot be empty")
}

# Remove duplicates from the array.
#
# $1 (array): An array of items with defined relational operator '='.
#
# > :put [$DeduplicateArray ({1;2;3;1})]
# 1;2;3
#
:global DeduplicateArray do={
    :local varDuplicatesIdx ({})

    :for i from=([:len $1] - 1) to=0 step=1 do={
        :local j ($i - 1)
        :while ($j >= 0 and $varDuplicatesIdx->"$i" != true) do={
            :if ($1->$i = $1->$j) do={
                :set ($varDuplicatesIdx->"$i") true
            }

            :set j ($j - 1)
        }
    }

    :local varArray ({})
    :for i from=0 to=([:len $1] - 1) step=1 do={
        :if ($varDuplicatesIdx->"$i" != true) do={
            :set varArray ($varArray , $1->$i)
        }
    }

    :return $varArray
}

# Remove duplicates from an array of strings.
#
# $1 (array): An array of strings.
# [compact] (bool): Whether empty values are removed; defaults to true
#
# > :put [$DeduplicateStrArray ({"1";"2";"3";"1"})]
# "1";"2";"3"
#
:global DeduplicateStrArray do={
    :global GetArrayKeys

    :local varShouldCompact true
    :if ([:len $compact] != 0) do={
        :if ([[:parse "[:tobool $compact]"]] = false) do={
            :set varShouldCompact false
        }
    }

    :local varTmp ({})
    :foreach varI in=$1 do={
        :if ($varShouldCompact = false or [:len $varI] > 0) do={
            :set ($varTmp->$varI) 1
        }
    }
    :return [$GetArrayKeys $varTmp]
}

# Get all keys of an array.
#
# $1 (array): An array.
#
# > :put [$GetArrayKeys ({"a"=1;"b"=2;3;4;5})]
# 0;1;2;a;b
#
:global GetArrayKeys do={
    :local varTmp ({})
    :foreach k,v in=$1 do={ :set varTmp ($varTmp , {$k}) }
    :return $varTmp
}

# Get all values of an array.
#
# $1 (array): An array.
#
# > :put [$GetArrayValues ({"a"=1;"b"=2;3;4;5})]
# 3;4;5;1;2
#
:global GetArrayValues do={
    :local varTmp ({})
    :foreach k,v in=$1 do={ :set varTmp ($varTmp , {$v}) }
    :return $varTmp
}

# Map values of the array using the given mapping function.
#
# $1 (array): An array.
# [$2] (func): A mapping function, takes one argument; defaults to :tostr
# [compact] (bool): Whether empty values are removed; defaults to true
#
# > :put [$MapArray ({"a"=1;"b"="";3;"";5})]
# 3;5;1
#
:global MapArray do={
    :local varArr $1

    :local funcTransform $2
    :if ([:typeof $funcTransform] = "nothing") do={
        :set funcTransform do={ :return [:tostr $1] }
    }

    :local varShouldCompact true
    :if ([:len $compact] != 0) do={
        :if ([[:parse "[:tobool $compact]"]] = false) do={
            :set varShouldCompact false
        }
    }

    :local varResult ({})
    :foreach varI in=$varArr do={
        :local varTransformedItem [$funcTransform $varI]
        :if ($varShouldCompact = false or [:len $varTransformedItem] > 0) do={
            :if ([:typeof $varTransformedItem] = "array") do={
                :set varResult ($varResult , {$varTransformedItem})
            } else={
                :set varResult ($varResult , $varTransformedItem)
            }
        }
    }

    :return $varResult
}

# Concatenate elements of the array, adding the given separator between each element.
#
# $1 (array): An array
# [$2] (str): A separator string; defaults to ","
# <named arguments of $MapArray>
#
# > :put [$JoinArray ({"a"=1;"b"=2;3;4;5})]
# 3,4,5,1,2
#
:global JoinArray do={
    :global MapArray

    :local varArr [$MapArray $1 compact=$compact]
    :local varSep $2

    :if ([:typeof $varSep] = "nothing") do={
        :set varSep ","
    }

    :local varResult ""
    :local varLen [:len $varArr]
    :local varIdx 0
    :foreach varI in=$varArr do={
        :set varResult ($varResult . $varI)
        :set varIdx ($varIdx + 1)
        :if ($varIdx != $varLen) do={ :set varResult ($varResult . $varSep)}
    }

    :return $varResult
}
