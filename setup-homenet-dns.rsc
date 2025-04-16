#!rsc by RouterOS

:global GlobalFunctionsReady;
:while ($GlobalFunctionsReady != true) do={ :delay 500ms; }

:global ScriptLock
:if ([$ScriptLock [:jobname]] = false) do={ :error false }

:global HomenetDNS
($HomenetDNS->"Main")
