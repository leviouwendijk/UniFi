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

    /// A connected client (UniFi calls these stations). Fields vary by client type, so all but `id` are optional.
    public enum Station {
        public struct Overview: Decodable, Sendable {
            public let id: UUID
            public let name: String?
            public let type: String?
            public let ipAddress: String?
            public let macAddress: String?
            public let connectedAt: String?
            public let uplinkDeviceId: UUID?
        }
    }

    /// An adopted UniFi device (gateway, switch, access point).
    public enum Device {
        public struct Overview: Decodable, Sendable {
            public let id: UUID
            public let name: String?
            public let model: String?
            public let macAddress: String?
            public let ipAddress: String?
            public let state: String?
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
                public struct PortMatch: Decodable, Sendable {
                    public let type: String
                    public let value: Int?
                    public let start: Int?
                    public let stop: Int?
                }

                public struct PortFilter: Decodable, Sendable {
                    public let type: String
                    public let matchOpposite: Bool?
                    public let items: [PortMatch]?
                    public let trafficMatchingListId: UUID?
                }

                public struct NetworkFilter: Decodable, Sendable {
                    public let networkIds: [UUID]
                    public let matchOpposite: Bool
                }

                public struct AddressMatch: Decodable, Sendable {
                    public let type: String
                    public let value: String?
                }

                public struct IPAddressFilter: Decodable, Sendable {
                    public let type: String?
                    public let matchOpposite: Bool?
                    public let items: [AddressMatch]?
                }

                public struct MACAddressFilter: Decodable, Sendable {
                    public let macAddresses: [String]?
                }

                public let type: String
                public let portFilter: PortFilter?
                public let networkFilter: NetworkFilter?
                public let ipAddressFilter: IPAddressFilter?
                public let macAddressFilter: MACAddressFilter?
            }

            public let zoneId: UUID
            public let trafficFilter: TrafficFilter?
        }

        public struct ProtocolScope: Decodable, Sendable {
            public struct ProtocolFilter: Decodable, Sendable {
                public struct NamedProtocol: Decodable, Sendable {
                    public let name: String
                }

                public struct Preset: Decodable, Sendable {
                    public let type: String?
                }

                public let type: String
                public let matchOpposite: Bool?
                public let `protocol`: NamedProtocol?
                public let preset: Preset?
                public let protocolNumber: Int?
            }

            public let ipVersion: String
            public let protocolFilter: ProtocolFilter?
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
            public let reportFlowEnabled: Bool?
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
