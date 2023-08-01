Available scripts
=================

* [mod/ipv6-functions](mod/ipv6-functions): Utility functions to maintain IPv6 config on RouterOS
* [mod/ipv6-structured](mod/ipv6-structured): Structured view of the IPv6 address
* [ipv6-dns](ipv6-dns): Install or update DNS record for given hosts
* [ipv6-npt](ipv6-npt): Install or update NPTv6 rules for a given prefix

For detailed documentation consult corresponding files.

Installation
============

Scripts are designed to extend @eworm-de's excellent [routeros-scripts](https://github.com/eworm-de/routeros-scripts) project, it's a prerequisite.

E.g. ipv6-dns can be installed via:

    $ScriptInstallUpdate ipv6-dns "base-url=https://raw.githubusercontent.com/Kentzo/routeros-scripts-custom/main/"

Note that scripts may depend on modules in *mod/\**, check the header before installation.
