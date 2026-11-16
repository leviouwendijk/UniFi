import Arguments
import Foundation
import UniFi

enum SitesCommand: RunnableArgumentCommand {
    static let name = "sites"

    static func components() throws -> [CommandComponentLowerable] {
        ([about("List sites on the gateway.")] as [CommandComponentLowerable]) + CLIOptions.connection()
    }

    static func run(_ invocation: ParsedInvocation) async throws {
        let context = try CLIContext(invocation)
        let sites = try await collect { try await context.client.network.sites.list(page: $0) }
        printTable(
            ["ID", "REFERENCE", "NAME"],
            sites.map { [$0.id.uuidString.lowercased(), $0.internalReference, $0.name] }
        )
    }
}

enum NetworksCommand: RunnableArgumentCommand {
    static let name = "networks"

    static func components() throws -> [CommandComponentLowerable] {
        ([about("List networks (VLANs) and their firewall zones.")] as [CommandComponentLowerable]) + CLIOptions.site()
    }

    static func run(_ invocation: ParsedInvocation) async throws {
        let context = try CLIContext(invocation)
        let site = try await context.site(invocation)
        let networks = try await collect { try await site.networks.list(page: $0) }
        let zones = try await collect { try await site.firewall.zones.list(page: $0) }
        let zoneNames = Dictionary(zones.map { ($0.id, $0.name) }, uniquingKeysWith: { first, _ in first })

        printTable(
            ["VLAN", "NAME", "ENABLED", "MANAGEMENT", "ZONE", "ID"],
            networks.sorted { $0.vlanId < $1.vlanId }.map { network in
                [
                    String(network.vlanId),
                    network.name,
                    network.enabled ? "yes" : "no",
                    network.management,
                    network.zoneId.flatMap { zoneNames[$0] } ?? "-",
                    network.id.uuidString.lowercased(),
                ]
            }
        )
    }
}

enum ZonesCommand: RunnableArgumentCommand {
    static let name = "zones"

    static func components() throws -> [CommandComponentLowerable] {
        ([about("List firewall zones and the networks in each.")] as [CommandComponentLowerable]) + CLIOptions.site()
    }

    static func run(_ invocation: ParsedInvocation) async throws {
        let context = try CLIContext(invocation)
        let site = try await context.site(invocation)
        let zones = try await collect { try await site.firewall.zones.list(page: $0) }
        let networks = try await collect { try await site.networks.list(page: $0) }
        let networkNames = Dictionary(networks.map { ($0.id, $0.name) }, uniquingKeysWith: { first, _ in first })

        printTable(
            ["ZONE", "ORIGIN", "NETWORKS", "ID"],
            zones.sorted { $0.name < $1.name }.map { zone in
                [
                    zone.name,
                    zone.metadata.origin,
                    zone.networkIds.map { networkNames[$0] ?? $0.short }.joined(separator: ", "),
                    zone.id.uuidString.lowercased(),
                ]
            }
        )
    }
}

enum PoliciesCommand: RunnableArgumentCommand {
    static let name = "policies"

    static func components() throws -> [CommandComponentLowerable] {
        let base: [CommandComponentLowerable] = [
            about("List firewall policies in evaluation order, with zones, protocol and ports resolved."),
            flag(
                "disabled",
                negation: .none,
                help: "Include disabled policies."
            ),
        ]
        return base + CLIOptions.site()
    }

    static func run(_ invocation: ParsedInvocation) async throws {
        let includeDisabled = try invocation.flag("disabled")
        let context = try CLIContext(invocation)
        let site = try await context.site(invocation)
        let policies = try await collect { try await site.firewall.policies.list(page: $0) }
        let zones = try await collect { try await site.firewall.zones.list(page: $0) }
        let networks = try await collect { try await site.networks.list(page: $0) }
        let zoneNames = Dictionary(zones.map { ($0.id, $0.name) }, uniquingKeysWith: { first, _ in first })
        let networkNames = Dictionary(networks.map { ($0.id, $0.name) }, uniquingKeysWith: { first, _ in first })
        let clients = (try? await collect { try await site.clients.list(page: $0) }) ?? []
        let macNames = Dictionary(
            clients.compactMap { client in
                client.macAddress.map { ($0.lowercased(), client.name ?? $0) }
            },
            uniquingKeysWith: { first, _ in first }
        )

        func endpoint(_ value: UniFi.Firewall.Policy.Endpoint) -> String {
            var text = zoneNames[value.zoneId] ?? value.zoneId.short
            if let filter = value.trafficFilter?.networkFilter {
                let names = filter.networkIds.map { networkNames[$0] ?? $0.short }.joined(separator: ",")
                text += filter.matchOpposite ? " !{\(names)}" : " {\(names)}"
            }
            if let filter = value.trafficFilter?.ipAddressFilter {
                let addresses = (filter.items ?? []).compactMap(\.value).joined(separator: ",")
                text += (filter.matchOpposite ?? false) ? " !ip[\(addresses)]" : " ip[\(addresses)]"
            }
            if let macs = value.trafficFilter?.macAddressFilter?.macAddresses {
                text += " mac[\(macs.map { macNames[$0.lowercased()] ?? $0 }.joined(separator: ","))]"
            }
            return text
        }

        func ports(_ value: UniFi.Firewall.Policy.Endpoint) -> String {
            guard let filter = value.trafficFilter?.portFilter else { return "any" }
            if let list = filter.trafficMatchingListId {
                return "list:\(list.short)"
            }
            let items = (filter.items ?? []).map { item -> String in
                if let single = item.value { return String(single) }
                if let start = item.start, let stop = item.stop { return "\(start)-\(stop)" }
                return item.type
            }
            let joined = items.isEmpty ? filter.type : items.joined(separator: ",")
            return (filter.matchOpposite ?? false) ? "!\(joined)" : joined
        }

        func proto(_ scope: UniFi.Firewall.Policy.ProtocolScope) -> String {
            guard let filter = scope.protocolFilter else { return scope.ipVersion.lowercased() }
            let name = filter.protocol?.name
                ?? filter.preset?.type
                ?? filter.protocolNumber.map { "proto \($0)" }
                ?? filter.type
            return (filter.matchOpposite ?? false) ? "!\(name)" : name
        }

        let rows = policies
            .filter { includeDisabled || $0.enabled }
            .sorted { $0.index < $1.index }
            .map { policy in
                [
                    String(policy.index),
                    policy.enabled ? "on" : "off",
                    policy.action.type,
                    endpoint(policy.source),
                    endpoint(policy.destination),
                    proto(policy.ipProtocolScope),
                    ports(policy.destination),
                    policy.connectionStateFilter.map { $0.map { $0.lowercased() }.joined(separator: ",") } ?? "all",
                    policy.metadata.origin,
                    policy.name,
                ]
            }

        printTable(["IDX", "STATE", "ACTION", "SOURCE", "DESTINATION", "PROTO", "DST PORTS", "CONN", "ORIGIN", "NAME"], rows)
    }
}

enum ClientsCommand: RunnableArgumentCommand {
    static let name = "clients"

    static func components() throws -> [CommandComponentLowerable] {
        let base: [CommandComponentLowerable] = [
            about("List connected clients sorted by IP address."),
            opt(
                "match",
                as: String.self,
                help: "Only show clients whose name, IP or MAC contains this text."
            ),
        ]
        return base + CLIOptions.site()
    }

    static func run(_ invocation: ParsedInvocation) async throws {
        let match = try invocation.value("match", as: String.self)?.lowercased()
        let context = try CLIContext(invocation)
        let site = try await context.site(invocation)
        let clients = try await collect { try await site.clients.list(page: $0) }
        let devices = try await collect { try await site.devices.list(page: $0) }
        let deviceNames = Dictionary(devices.map { ($0.id, $0.name ?? $0.id.short) }, uniquingKeysWith: { first, _ in first })

        let rows = clients
            .filter { client in
                guard let match else { return true }
                return [client.name, client.ipAddress, client.macAddress]
                    .compactMap { $0?.lowercased() }
                    .contains { $0.contains(match) }
            }
            .sorted { ipv4SortKey($0.ipAddress).lexicographicallyPrecedes(ipv4SortKey($1.ipAddress)) }
            .map { client in
                [
                    client.ipAddress ?? "-",
                    client.name ?? "-",
                    client.type ?? "-",
                    client.macAddress ?? "-",
                    client.uplinkDeviceId.flatMap { deviceNames[$0] } ?? "-",
                ]
            }

        printTable(["IP", "NAME", "TYPE", "MAC", "UPLINK"], rows)
    }
}

enum DevicesCommand: RunnableArgumentCommand {
    static let name = "devices"

    static func components() throws -> [CommandComponentLowerable] {
        ([about("List adopted UniFi devices.")] as [CommandComponentLowerable]) + CLIOptions.site()
    }

    static func run(_ invocation: ParsedInvocation) async throws {
        let context = try CLIContext(invocation)
        let site = try await context.site(invocation)
        let devices = try await collect { try await site.devices.list(page: $0) }

        printTable(
            ["IP", "NAME", "MODEL", "STATE", "MAC", "ID"],
            devices
                .sorted { ipv4SortKey($0.ipAddress).lexicographicallyPrecedes(ipv4SortKey($1.ipAddress)) }
                .map { device in
                    [
                        device.ipAddress ?? "-",
                        device.name ?? "-",
                        device.model ?? "-",
                        device.state ?? "-",
                        device.macAddress ?? "-",
                        device.id.uuidString.lowercased(),
                    ]
                }
        )
    }
}

enum RawCommand: RunnableArgumentCommand {
    static let name = "raw"

    static func components() throws -> [CommandComponentLowerable] {
        let base: [CommandComponentLowerable] = [
            about("GET an integration API path (relative to /proxy/network/integration/v1) and print the JSON. '{site}' is replaced with the resolved site id."),
            arg(
                "path",
                as: String.self,
                help: "For example /sites/{site}/networks/<id>"
            ),
            opt(
                "offset",
                as: Int.self,
                help: "Page offset."
            ),
            opt(
                "limit",
                as: Int.self,
                help: "Page size."
            ),
        ]
        return base + CLIOptions.site()
    }

    static func run(_ invocation: ParsedInvocation) async throws {
        var path = try invocation.require("path", as: String.self)
        let offset = try invocation.value("offset", as: Int.self)
        let limit = try invocation.value("limit", as: Int.self)
        let context = try CLIContext(invocation)

        if path.contains("{site}") {
            let site = try await context.site(invocation)
            path = path.replacingOccurrences(of: "{site}", with: site.id.uuidString.lowercased())
        }

        let page: UniFi.PageQuery? = (offset != nil || limit != nil)
            ? try UniFi.PageQuery(offset: offset ?? 0, limit: limit ?? 25)
            : nil

        let body = try await context.client.network.raw(path, page: page)
        guard let object = try? JSONSerialization.jsonObject(with: body) else {
            throw CLIFailure.invalidJSON
        }
        let pretty = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
        FileHandle.standardOutput.write(pretty)
        FileHandle.standardOutput.write(Data("\n".utf8))
    }
}
