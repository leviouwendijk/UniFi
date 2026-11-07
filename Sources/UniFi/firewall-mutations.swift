import Foundation

extension UniFi.Firewall.Zone {
    public struct Draft: Encodable, Sendable {
        public let name: String
        public let networkIds: [UUID]

        public init(name: String, networkIds: [UUID]) throws {
            guard !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  Set(networkIds).count == networkIds.count else {
                throw UniFi.Failure.invalidMutation
            }
            self.name = name
            self.networkIds = networkIds
        }
    }
}

extension UniFi.Firewall.Policy {
    public struct TelemetryPatch: Encodable, Sendable {
        public let loggingEnabled: Bool?
        public let reportFlowEnabled: Bool?

        public init(loggingEnabled: Bool? = nil, reportFlowEnabled: Bool? = nil) throws {
            guard loggingEnabled != nil || reportFlowEnabled != nil else {
                throw UniFi.Failure.invalidMutation
            }
            self.loggingEnabled = loggingEnabled
            self.reportFlowEnabled = reportFlowEnabled
        }
    }
}

extension UniFi {
    public enum MutationReview: Sendable {
        case createZone(siteID: UUID, proposed: Firewall.Zone.Draft)
        case updateZone(siteID: UUID, before: Firewall.Zone, proposed: Firewall.Zone.Draft)
        case deleteZone(siteID: UUID, before: Firewall.Zone)
        case patchPolicyTelemetry(siteID: UUID, before: Firewall.Policy, proposed: Firewall.Policy.TelemetryPatch)
    }

    public protocol MutationApprover: Sendable {
        func approve(_ review: MutationReview) async throws
    }

    public struct Mutations: Sendable {
        fileprivate let backend: Backend
        fileprivate let approver: any MutationApprover

        public func site(_ id: UUID) -> MutationSite {
            MutationSite(backend: backend, approver: approver, id: id)
        }
    }

    public struct MutationSite: Sendable {
        fileprivate let backend: Backend
        fileprivate let approver: any MutationApprover
        public let id: UUID

        public var firewall: MutationFirewall {
            MutationFirewall(backend: backend, approver: approver, siteID: id)
        }
    }

    public struct MutationFirewall: Sendable {
        fileprivate let backend: Backend
        fileprivate let approver: any MutationApprover
        public let siteID: UUID

        public var zones: MutationZones {
            MutationZones(backend: backend, approver: approver, siteID: siteID)
        }

        public var policies: MutationPolicies {
            MutationPolicies(backend: backend, approver: approver, siteID: siteID)
        }
    }

    public struct MutationZones: Sendable {
        fileprivate let backend: Backend
        fileprivate let approver: any MutationApprover
        public let siteID: UUID
        private var base: String { "/sites/\(siteID.uuidString.lowercased())/firewall/zones" }

        public func create(_ proposed: Firewall.Zone.Draft) async throws -> Firewall.Zone {
            try await authorize(.createZone(siteID: siteID, proposed: proposed))
            return try await backend.write(.post, path: base, body: proposed, expectedStatus: 201)
        }

        public func update(_ id: UUID, to proposed: Firewall.Zone.Draft) async throws -> Firewall.Zone {
            let path = "\(base)/\(id.uuidString.lowercased())"
            let before: Firewall.Zone = try await backend.get(path)
            try await authorize(.updateZone(siteID: siteID, before: before, proposed: proposed))
            return try await backend.write(.put, path: path, body: proposed, expectedStatus: 200)
        }

        public func delete(_ id: UUID) async throws {
            let path = "\(base)/\(id.uuidString.lowercased())"
            let before: Firewall.Zone = try await backend.get(path)
            try await authorize(.deleteZone(siteID: siteID, before: before))
            try await backend.remove(path)
        }

        private func authorize(_ review: MutationReview) async throws {
            do {
                try await approver.approve(review)
            } catch {
                throw Failure.mutationNotApproved
            }
        }
    }

    public struct MutationPolicies: Sendable {
        fileprivate let backend: Backend
        fileprivate let approver: any MutationApprover
        public let siteID: UUID
        private var base: String { "/sites/\(siteID.uuidString.lowercased())/firewall/policies" }

        public func patchTelemetry(
            _ id: UUID,
            to proposed: Firewall.Policy.TelemetryPatch,
            verifyBefore: @Sendable (Firewall.Policy) throws -> Void = { _ in }
        ) async throws -> Firewall.Policy {
            let path = "\(base)/\(id.uuidString.lowercased())"
            let before: Firewall.Policy = try await backend.get(path)
            try verifyBefore(before)
            do {
                try await approver.approve(.patchPolicyTelemetry(siteID: siteID, before: before, proposed: proposed))
            } catch {
                throw Failure.mutationNotApproved
            }
            return try await backend.write(.patch, path: path, body: proposed, expectedStatus: 200)
        }
    }
}

extension UniFi.Client {
    /// The host must supply an authentic, out-of-band approval implementation.
    /// This is not a security boundary against code able to inject its own approver.
    public func mutations(approvedBy approver: any UniFi.MutationApprover) -> UniFi.Mutations {
        UniFi.Mutations(backend: backend, approver: approver)
    }
}
