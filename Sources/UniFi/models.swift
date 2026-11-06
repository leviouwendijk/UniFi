import Foundation

extension UniFi {
    public struct Metadata: Decodable, Sendable {
        public let origin: String
    }

    public enum Site {
        public struct Overview: Decodable, Sendable {
            public let id: UUID
            public let internalReference: String
            public let name: String
        }
    }

    public enum Network {
        public struct Overview: Decodable, Sendable {
            public let id: UUID
            public let name: String
            public let management: String
            public let vlanId: Int
            public let `default`: Bool
            public let enabled: Bool
            public let metadata: Metadata
            public let zoneId: UUID?
        }

        public struct Details: Decodable, Sendable {
            public let id: UUID
            public let name: String
            public let management: String
            public let vlanId: Int
            public let `default`: Bool
            public let enabled: Bool
            public let metadata: Metadata
            public let zoneId: UUID?
        }
    }

    public enum Firewall {
        public struct Zone: Decodable, Sendable {
            public let id: UUID
            public let metadata: Metadata
            public let name: String
            public let networkIds: [UUID]
        }

        public struct Policy: Decodable, Sendable {
            public struct Action: Decodable, Sendable {
                public let type: String
                public let allowReturnTraffic: Bool?
            }

            public struct Endpoint: Decodable, Sendable {
                public struct TrafficFilter: Decodable, Sendable {
                    public let type: String
                }

                public let zoneId: UUID
                public let trafficFilter: TrafficFilter?
            }

            public struct ProtocolScope: Decodable, Sendable {
                public let ipVersion: String
            }

            public struct Schedule: Decodable, Sendable {
                public let mode: String
            }

            public let id: UUID
            public let name: String
            public let description: String?
            public let index: Int
            public let enabled: Bool
            public let loggingEnabled: Bool
            public let reportFlowEnabled: Bool
            public let metadata: Metadata
            public let action: Action
            public let source: Endpoint
            public let destination: Endpoint
            public let ipProtocolScope: ProtocolScope
            public let connectionStateFilter: [String]?
            public let ipsecFilter: String?
            public let schedule: Schedule?
        }
    }
}
