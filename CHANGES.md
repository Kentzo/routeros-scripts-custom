## 1.0.2

### Bugfixes

- `$StructureIP6AddressCommon` loses address bits when parsing ip6-prefix on 7.21

## 1.0.1

### Bugfixes

- `$MakeIP6PrefixMask` produced 0001, 0011 and 0111 instead of 1000, 1100 and 1110
- `$StructureIP6AddressCommon` fails to parse ip6-prefix on 7.21
