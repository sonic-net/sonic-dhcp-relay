# Copilot Instructions for sonic-dhcp-relay

## Project Overview

sonic-dhcp-relay implements DHCP relay agent functionality for SONiC switches. It includes both DHCPv4 and DHCPv6 relay agents that forward DHCP packets between clients on connected subnets and remote DHCP servers. This is a critical L3 network service that enables dynamic IP address assignment across routed networks.

## Architecture

```
sonic-dhcp-relay/
├── dhcp4relay/          # DHCPv4 relay implementation
│   ├── src/             # C source code
│   └── Makefile         # Build rules
├── dhcp6relay/          # DHCPv6 relay implementation
│   ├── src/             # C source code
│   └── Makefile         # Build rules
├── .azure-pipelines/    # CI/CD pipeline definitions
└── .github/             # GitHub configuration
```

### Key Concepts
- **DHCP relay**: Forwards DHCP discover/request/reply between VLANs/subnets and DHCP servers
- **DHCPv4 (RFC 2131)**: Option 82 (relay agent information) support
- **DHCPv6 (RFC 3315)**: Relay-forward/relay-reply message handling
- **Interface binding**: Relay binds to specific interfaces and listens for DHCP traffic
- **Server configuration**: Relay servers configured via CONFIG_DB DHCP_RELAY table

## Language & Style

- **Primary language**: C
- **Indentation**: 4 spaces
- **Naming conventions**:
  - Functions: `snake_case`
  - Constants/macros: `UPPER_CASE`
  - Structs: `snake_case` or `PascalCase`
  - File names: lowercase
- **Comments**: C-style (`/* */`) for blocks, `//` for inline

## Build Instructions

```bash
# Build DHCPv4 relay
cd dhcp4relay
make

# Build DHCPv6 relay
cd dhcp6relay
make

# Build Debian package (from sonic-buildimage context)
dpkg-buildpackage -us -uc -b
```

## Testing

- CI runs on Azure Pipelines
- Integration tests are in the sonic-mgmt repo
- Packet-level testing with PTF
- Test with VS (virtual switch) platform for basic validation

## PR Guidelines

- **Commit format**: `[dhcp4relay|dhcp6relay]: Description`
- **Signed-off-by**: REQUIRED (`git commit -s`)
- **CLA**: Sign Linux Foundation EasyCLA
- **RFC compliance**: Must follow DHCP RFCs strictly
- **Testing**: Validate with both IPv4 and IPv6 scenarios

## Common Patterns

### Packet Processing Flow
```
Client DHCP packet → relay agent (listening on interface)
→ Add relay information (Option 82 / relay-forward)
→ Forward to configured DHCP server(s)
→ Server response → strip relay info → forward to client
```

### CONFIG_DB Integration
```
DHCP_RELAY|Vlan100 → { "dhcp_servers": ["10.0.0.1", "10.0.0.2"] }
```

## Dependencies

- **libc**: Standard C library
- **libpcap**: Packet capture (for raw socket operations)
- **sonic-swss-common**: Database connectivity (via C bindings)
- **CONFIG_DB**: DHCP relay configuration

## Gotchas

- **Raw sockets**: DHCP relay uses raw sockets — requires appropriate permissions
- **VLAN interfaces**: Relay must bind to VLAN interfaces, not physical ports
- **Option 82**: Incorrect option 82 handling breaks DHCP for the entire subnet
- **Dual-stack**: Changes must consider both DHCPv4 and DHCPv6 independently
- **Multi-ASIC**: Must handle packets correctly across ASIC namespaces
- **Performance**: DHCP storms can overwhelm the relay — handle gracefully
- **Config reload**: Relay must handle configuration changes without dropping in-flight requests
- **Packet validation**: Always validate DHCP packet structure before processing
