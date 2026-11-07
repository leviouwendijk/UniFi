import Foundation
import Primitives
import UniFi

public enum UniFiPlanning {
    public enum Failure: Error, Sendable, Equatable {
        case duplicate_identity
        case overlapping_membership(UUID)
        case inconsistent_membership(UUID)
        case unknown_network(UUID)
        case unknown_zone(UUID)
        case unknown_policy(UUID)
        case duplicate_change
        case invalid_change
        case no_changes
        case stale_snapshot
        case verification_failed
        case incomplete_page
        case incomplete_snapshot
    }

    public struct Network: Sendable, Codable, Hashable {
        public let id: UUID
        public let name: String
        public let vlan_id: Int
        public let enabled: Bool
        public let zone_id: UUID?

        public init(_ value: UniFi.Network.Overview) {
            id = value.id
            name = value.name
            vlan_id = value.vlanId
            enabled = value.enabled
            zone_id = value.zoneId
        }
    }

    public struct Zone: Sendable, Codable, Hashable {
        public let id: UUID
        public let name: String
        public internal(set) var network_ids: [UUID]
        public let origin: String

        public init(_ value: UniFi.Firewall.Zone) {
            id = value.id
            name = value.name
            network_ids = value.networkIds
            origin = value.metadata.origin
        }
    }

    public struct PortMatch: Sendable, Codable, Hashable {
        public let type: String
        public let value: Int?
        public let start: Int?
        public let stop: Int?

        public init(_ value: UniFi.Firewall.Policy.Endpoint.TrafficFilter.PortMatch) {
            type = value.type
            self.value = value.value
            start = value.start
            stop = value.stop
        }
    }

    public struct PortSelection: Sendable, Codable, Hashable {
        public let type: String
        public let match_opposite: Bool?
        public let items: [PortMatch]?
        public let traffic_matching_list_id: UUID?

        public init(_ value: UniFi.Firewall.Policy.Endpoint.TrafficFilter.PortFilter) {
            type = value.type
            match_opposite = value.matchOpposite
            items = value.items?.map(PortMatch.init)
            traffic_matching_list_id = value.trafficMatchingListId
        }
    }

    public struct TrafficSelection: Sendable, Codable, Hashable {
        public let type: String
        public let network_ids: [UUID]?
        public let network_match_opposite: Bool?
        public let ports: PortSelection?

        public init(_ value: UniFi.Firewall.Policy.Endpoint.TrafficFilter) {
            type = value.type
            network_ids = value.networkFilter?.networkIds
            network_match_opposite = value.networkFilter?.matchOpposite
            ports = value.portFilter.map(PortSelection.init)
        }
    }

    public struct ProtocolSelection: Sendable, Codable, Hashable {
        public let type: String
        public let match_opposite: Bool?
        public let name: String?
        public let preset: String?
        public let number: Int?

        public init(_ value: UniFi.Firewall.Policy.ProtocolScope.ProtocolFilter) {
            type = value.type
            match_opposite = value.matchOpposite
            name = value.`protocol`?.name
            preset = value.preset?.type
            number = value.protocolNumber
        }
    }

    public struct Policy: Sendable, Codable, Hashable {
        public let id: UUID
        public let name: String
        public let description: String?
        public let index: Int
        public let enabled: Bool
        public internal(set) var logging_enabled: Bool
        public internal(set) var report_flow_enabled: Bool?
        public let origin: String
        public let action: String
        public let return_traffic: Bool?
        public let source_zone_id: UUID
        public let destination_zone_id: UUID
        public let source_filter: String?
        public let destination_filter: String?
        public let ip_version: String
        public let connection_states: [String]?
        public let ipsec_filter: String?
        public let schedule: String?
        public let source_selection: TrafficSelection?
        public let destination_selection: TrafficSelection?
        public let protocol_selection: ProtocolSelection?

        public init(_ value: UniFi.Firewall.Policy) {
            id = value.id
            name = value.name
            description = value.description
            index = value.index
            enabled = value.enabled
            logging_enabled = value.loggingEnabled
            report_flow_enabled = value.reportFlowEnabled
            origin = value.metadata.origin
            action = value.action.type
            return_traffic = value.action.allowReturnTraffic
            source_zone_id = value.source.zoneId
            destination_zone_id = value.destination.zoneId
            source_filter = value.source.trafficFilter?.type
            destination_filter = value.destination.trafficFilter?.type
            ip_version = value.ipProtocolScope.ipVersion
            connection_states = value.connectionStateFilter
            ipsec_filter = value.ipsecFilter
            schedule = value.schedule?.mode
            source_selection = value.source.trafficFilter.map(TrafficSelection.init)
            destination_selection = value.destination.trafficFilter.map(TrafficSelection.init)
            protocol_selection = value.ipProtocolScope.protocolFilter.map(ProtocolSelection.init)
        }
    }

    public enum Node: Sendable, Codable, Hashable {
        case network(Network)
        case zone(Zone)
        case unresolved_network(UUID)
        case unresolved_zone(UUID)
    }

    public enum Relationship: Sendable, Codable, Hashable {
        case membership
        case policy(Policy)
    }

    public struct Snapshot: Sendable, Codable, Hashable {
        public let site_id: UUID
        public let networks: [Network]
        public let zones: [Zone]
        public let policies: [Policy]

        public var unresolved_network_ids: Set<UUID> {
            Set(zones.flatMap(\.network_ids))
                .subtracting(networks.map(\.id))
        }

        public var unresolved_zone_ids: Set<UUID> {
            let referenced = Set(
                networks.compactMap(\.zone_id) +
                policies.flatMap {
                    [$0.source_zone_id, $0.destination_zone_id]
                }
            )
            return referenced.subtracting(zones.map(\.id))
        }

        public var reference_complete: Bool {
            unresolved_network_ids.isEmpty && unresolved_zone_ids.isEmpty
        }

        public init(
            site_id: UUID,
            networks: [Network],
            zones: [Zone],
            policies: [Policy]
        ) throws {
            func unique(_ ids: [UUID]) -> Bool {
                Set(ids).count == ids.count
            }
            guard unique(networks.map(\.id)), unique(zones.map(\.id)),
                  unique(policies.map(\.id)) else {
                throw Failure.duplicate_identity
            }
            var assigned_networks = Set<UUID>()
            var zone_for_network: [UUID: UUID] = [:]
            for zone in zones {
                guard unique(zone.network_ids) else { throw Failure.duplicate_identity }
                for id in zone.network_ids {
                    guard assigned_networks.insert(id).inserted else {
                        throw Failure.overlapping_membership(id)
                    }
                    zone_for_network[id] = zone.id
                }
            }
            for network in networks {
                if let zone_id = network.zone_id,
                   let assigned = zone_for_network[network.id],
                   assigned != zone_id {
                    throw Failure.inconsistent_membership(network.id)
                }
            }
            self.site_id = site_id
            self.networks = networks
            self.zones = zones
            self.policies = policies
        }

        public init(
            site_id: UUID,
            networks: [UniFi.Network.Overview],
            zones: [UniFi.Firewall.Zone],
            policies: [UniFi.Firewall.Policy]
        ) throws {
            try self.init(
                site_id: site_id,
                networks: networks.map(Network.init),
                zones: zones.map(Zone.init),
                policies: policies.map(Policy.init)
            )
        }

        private enum CodingKeys: String, CodingKey {
            case site_id, networks, zones, policies
        }

        public init(from decoder: Decoder) throws {
            let values = try decoder.container(keyedBy: CodingKeys.self)
            try self.init(
                site_id: values.decode(UUID.self, forKey: .site_id),
                networks: values.decode([Network].self, forKey: .networks),
                zones: values.decode([Zone].self, forKey: .zones),
                policies: values.decode([Policy].self, forKey: .policies)
            )
        }

        public func topology() throws -> Graph<String, Node, String, Relationship> {
            func key(_ id: UUID) -> String { id.uuidString.lowercased() }
            let nodes: [Graph<String, Node, String, Relationship>.Node] =
                networks.sorted { key($0.id) < key($1.id) }.map {
                    .init(id: "network/\(key($0.id))", value: .network($0))
                } + zones.sorted { key($0.id) < key($1.id) }.map {
                    .init(id: "zone/\(key($0.id))", value: .zone($0))
                } + unresolved_network_ids.sorted { key($0) < key($1) }.map {
                    .init(id: "network/\(key($0))", value: .unresolved_network($0))
                } + unresolved_zone_ids.sorted { key($0) < key($1) }.map {
                    .init(id: "zone/\(key($0))", value: .unresolved_zone($0))
                }
            var edges: [Graph<String, Node, String, Relationship>.Edge] = []
            for zone in zones.sorted(by: { key($0.id) < key($1.id) }) {
                for network_id in zone.network_ids.sorted(by: { key($0) < key($1) }) {
                    edges.append(.init(
                        id: "membership/\(key(zone.id))/\(key(network_id))",
                        source: "zone/\(key(zone.id))",
                        destination: "network/\(key(network_id))",
                        value: .membership
                    ))
                }
            }
            for policy in policies.sorted(by: { key($0.id) < key($1.id) }) {
                edges.append(.init(
                    id: "policy/\(key(policy.id))",
                    source: "zone/\(key(policy.source_zone_id))",
                    destination: "zone/\(key(policy.destination_zone_id))",
                    value: .policy(policy)
                ))
            }
            return try .init(nodes: nodes, edges: edges)
        }
    }
}
