import Foundation
import Errors
import UniFi

extension UniFiPlanning {
    /// Only safe categorical evidence crosses the agent boundary.
    public struct ReadFailure: SemanticError, Sendable, CustomStringConvertible {
        public enum Stage: String, Sendable {
            case sites
            case networks
            case zones
            case policies
            case validation
        }

        public enum Kind: String, Sendable {
            case decoding
            case http_status
            case pagination
            case validation
            case transport
            case credentials
            case inconsistent_data
            case unexpected
        }

        public enum ValidationIssue: String, Sendable {
            case duplicate_identity
            case unknown_network
            case unknown_zone
            case overlapping_membership
            case inconsistent_membership
            case other
        }

        public let stage: Stage
        public let kind: Kind
        public let http_status: Int?
        public let coding_path: [String]
        public let field: String?
        public let validation_issue: ValidationIssue?

        public init(
            stage: Stage,
            kind: Kind,
            http_status: Int? = nil,
            coding_path: [String] = [],
            field: String? = nil,
            validation_issue: ValidationIssue? = nil
        ) {
            self.stage = stage
            self.kind = kind
            self.http_status = http_status
            self.coding_path = Array(coding_path.prefix(16)).map(UniFi.DecodingFailure.safe_key)
            self.field = field.map(UniFi.DecodingFailure.safe_key)
            self.validation_issue = validation_issue
        }

        public init(stage: Stage, error: any Error) {
            if let failure = error as? UniFi.DecodingFailure {
                self.init(stage: stage, kind: .decoding,
                          coding_path: failure.coding_path, field: failure.field)
            } else if let failure = error as? UniFi.Failure {
                switch failure {
                case .httpStatus(let status):
                    self.init(stage: stage, kind: .http_status, http_status: status)
                case .transportFailure:
                    self.init(stage: stage, kind: .transport)
                case .credentialUnavailable, .invalidCredential:
                    self.init(stage: stage, kind: .credentials)
                default:
                    self.init(stage: stage, kind: .unexpected)
                }
            } else if let failure = error as? UniFiPlanning.Failure {
                switch failure {
                case .incomplete_page:
                    self.init(stage: stage, kind: .pagination)
                case .duplicate_identity:
                    self.init(stage: stage, kind: .validation, validation_issue: .duplicate_identity)
                case .unknown_network(_):
                    self.init(stage: stage, kind: .validation, validation_issue: .unknown_network)
                case .unknown_zone(_):
                    self.init(stage: stage, kind: .validation, validation_issue: .unknown_zone)
                case .overlapping_membership(_):
                    self.init(stage: stage, kind: .validation, validation_issue: .overlapping_membership)
                case .inconsistent_membership(_):
                    self.init(stage: stage, kind: .validation, validation_issue: .inconsistent_membership)
                default:
                    self.init(stage: stage, kind: .validation, validation_issue: .other)
                }
            } else {
                self.init(stage: stage, kind: .unexpected)
            }
        }

        public var description: String {
            var parts = ["stage=\(stage.rawValue)", "kind=\(kind.rawValue)"]
            if let http_status { parts.append("http_status=\(http_status)") }
            if !coding_path.isEmpty { parts.append("path=\(coding_path.joined(separator: "."))") }
            if let field { parts.append("field=\(field)") }
            if let validation_issue {
                parts.append("rule=\(validation_issue.rawValue)")
            }
            return parts.joined(separator: " ")
        }

        public var errorIdentity: ErrorIdentity {
            .init(namespace: "unifi.planning", code: kind.rawValue)
        }

        public var errorPresentation: ErrorPresentation {
            .init(message: "UniFi read failed: " + description)
        }

        public var errorDiagnosticFields: [ErrorDiagnosticField] {
            var fields: [ErrorDiagnosticField] = [
                .init(key: "stage", value: .string(stage.rawValue)),
                .init(key: "kind", value: .string(kind.rawValue)),
            ]
            if let http_status {
                fields.append(.init(key: "http_status", value: .integer(http_status)))
            }
            if !coding_path.isEmpty {
                fields.append(.init(key: "coding_path", value: .array(coding_path.map { .string($0) })))
            }
            if let field {
                fields.append(.init(key: "field", value: .string(field)))
            }
            if let validation_issue {
                fields.append(.init(
                    key: "validation_rule",
                    value: .string(validation_issue.rawValue)
                ))
            }
            return fields
        }
    }

    public struct Reader: Sendable {
        public let client: UniFi.Client

        public init(client: UniFi.Client) {
            self.client = client
        }

        public func list_sites() async throws -> [UniFi.Site.Overview] {
            do {
                return try await collect { page in
                    try await client.network.sites.list(page: page)
                }
            } catch {
                throw ReadFailure(stage: .sites, error: error)
            }
        }

        public func capture(site_id: UUID) async throws -> Snapshot {
            let site = client.network.site(site_id)
            let networks: [UniFi.Network.Overview]
            do {
                networks = try await collect { query in
                    try await site.networks.list(page: query)
                }
            } catch {
                throw ReadFailure(stage: .networks, error: error)
            }
            let zones: [UniFi.Firewall.Zone]
            do {
                zones = try await collect { query in
                    try await site.firewall.zones.list(page: query)
                }
            } catch {
                throw ReadFailure(stage: .zones, error: error)
            }
            let policies: [UniFi.Firewall.Policy]
            do {
                policies = try await collect { query in
                    try await site.firewall.policies.list(page: query)
                }
            } catch {
                throw ReadFailure(stage: .policies, error: error)
            }
            do {
                return try Snapshot(
                    site_id: site_id,
                    networks: networks,
                    zones: zones,
                    policies: policies
                )
            } catch {
                throw ReadFailure(stage: .validation, error: error)
            }
        }

        private func collect<Element: Decodable & Sendable>(
            _ fetch: (UniFi.PageQuery) async throws -> UniFi.Page<Element>
        ) async throws -> [Element] {
            var result: [Element] = []
            var total: Int?
            while true {
                let page = try await fetch(.init(offset: result.count, limit: 25))
                guard page.offset == result.count,
                      page.totalCount >= 0,
                      page.totalCount <= 10_000,
                      (total == nil || total == page.totalCount),
                      page.data.count <= 25,
                      result.count + page.data.count <= page.totalCount,
                      (!page.data.isEmpty || result.count == page.totalCount)
                else {
                    throw Failure.incomplete_page
                }
                total = page.totalCount
                result.append(contentsOf: page.data)
                if result.count == page.totalCount { return result }
            }
        }
    }
}
