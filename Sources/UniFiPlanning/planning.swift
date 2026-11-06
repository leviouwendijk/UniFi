import Difference
import Foundation

extension UniFiPlanning {
    public enum Change: Sendable, Codable, Hashable {
        case set_zone_networks(zone_id: UUID, network_ids: [UUID])
        case patch_policy_telemetry(policy_id: UUID, logging_enabled: Bool?, report_flow_enabled: Bool?)
    }

    public struct Plan: Sendable, Codable, Hashable {
        public let before: Snapshot
        public let after: Snapshot
        public let changes: [Change]
        public let presentation: DifferencePresentation

        private init(
            before: Snapshot,
            after: Snapshot,
            changes: [Change],
            presentation: DifferencePresentation
        ) {
            self.before = before
            self.after = after
            self.changes = changes
            self.presentation = presentation
        }

        public static func prepare(
            from snapshot: Snapshot,
            changes: [Change]
        ) throws -> Self {
            guard !changes.isEmpty else { throw Failure.no_changes }
            var zones = snapshot.zones
            var policies = snapshot.policies
            let known_networks = Set(snapshot.networks.map(\.id))
            var changed_keys = Set<String>()

            for change in changes {
                let key: String
                switch change {
                case .set_zone_networks(let id, let network_ids):
                    key = "zone/\(id.uuidString)"
                    guard Set(network_ids).count == network_ids.count else {
                        throw Failure.invalid_change
                    }
                    for network_id in network_ids where !known_networks.contains(network_id) {
                        throw Failure.unknown_network(network_id)
                    }
                    guard let index = zones.firstIndex(where: { $0.id == id }) else {
                        throw Failure.unknown_zone(id)
                    }
                    guard zones[index].origin == "USER_DEFINED" else {
                        throw Failure.invalid_change
                    }
                    zones[index].network_ids = network_ids

                case .patch_policy_telemetry(let id, let logging, let reporting):
                    key = "policy/\(id.uuidString)"
                    guard logging != nil || reporting != nil else {
                        throw Failure.invalid_change
                    }
                    guard let index = policies.firstIndex(where: { $0.id == id }) else {
                        throw Failure.unknown_policy(id)
                    }
                    guard policies[index].origin == "USER_DEFINED" else {
                        throw Failure.invalid_change
                    }
                    if let logging { policies[index].logging_enabled = logging }
                    if let reporting { policies[index].report_flow_enabled = reporting }
                }
                guard changed_keys.insert(key).inserted else {
                    throw Failure.duplicate_change
                }
            }
            let after = try Snapshot(
                site_id: snapshot.site_id,
                networks: snapshot.networks,
                zones: zones,
                policies: policies
            )
            let difference = GraphDiffer.make(
                before: try snapshot.topology(),
                after: try after.topology(),
                equivalent_node: ==,
                equivalent_edge: ==
            )
            guard difference.has_changes else { throw Failure.no_changes }
            let layout = try GraphDifferenceLayout.make(
                difference,
                nodeID: { $0 },
                edgeID: { $0 },
                presentingNode: { value in
                    switch value {
                    case .network(let network):
                        return .init(label: "Network", detail: "VLAN \(network.vlan_id); enabled \(network.enabled)")
                    case .zone(let zone):
                        return .init(label: "Firewall zone", detail: "\(zone.network_ids.count) network memberships")
                    }
                },
                presentingEdge: { value in
                    switch value {
                    case .membership:
                        return .init(label: "Zone membership")
                    case .policy(let policy):
                        let action: String
                        switch policy.action.uppercased() {
                        case "ALLOW", "BLOCK", "REJECT": action = policy.action.uppercased()
                        default: action = "UNRECOGNIZED"
                        }
                        return .init(
                            label: "Firewall policy",
                            detail: "\(action); enabled \(policy.enabled); logging \(policy.logging_enabled); reporting \(policy.report_flow_enabled)"
                        )
                    }
                }
            )
            return .init(
                before: snapshot,
                after: after,
                changes: changes,
                presentation: .init(graph: layout)
            )
        }

        private enum CodingKeys: String, CodingKey {
            case before, after, changes, presentation
        }

        public init(from decoder: Decoder) throws {
            let values = try decoder.container(keyedBy: CodingKeys.self)
            let before = try values.decode(Snapshot.self, forKey: .before)
            let changes = try values.decode([Change].self, forKey: .changes)
            let expected = try values.decode(Snapshot.self, forKey: .after)
            let presentation = try values.decode(DifferencePresentation.self, forKey: .presentation)
            let prepared = try Self.prepare(from: before, changes: changes)
            guard prepared.after == expected,
                  prepared.presentation == presentation
            else {
                throw Failure.invalid_change
            }
            self = prepared
        }

        /// Refuse application when the fetched state changed after planning.
        /// This does not authorize or execute a mutation.
        public func require_fresh(_ current: Snapshot) throws {
            guard current == before else { throw Failure.stale_snapshot }
        }

        /// Compare an independently fetched post-change snapshot against the
        /// expected modeled state. This does not prove packet-level behavior.
        public func verify(_ observed: Snapshot) throws {
            guard observed == after else { throw Failure.verification_failed }
        }
    }
}
