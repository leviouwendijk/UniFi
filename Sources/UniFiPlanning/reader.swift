import Foundation
import UniFi

extension UniFiPlanning {
    public struct Reader: Sendable {
        public let client: UniFi.Client

        public init(client: UniFi.Client) {
            self.client = client
        }

        public func list_sites() async throws -> [UniFi.Site.Overview] {
            try await collect { page in
                try await client.network.sites.list(page: page)
            }
        }

        public func capture(site_id: UUID) async throws -> Snapshot {
            let site = client.network.site(site_id)
            let networks = try await collect { query in
                try await site.networks.list(page: query)
            }
            let zones = try await collect { query in
                try await site.firewall.zones.list(page: query)
            }
            let policies = try await collect { query in
                try await site.firewall.policies.list(page: query)
            }
            return try Snapshot(
                site_id: site_id,
                networks: networks,
                zones: zones,
                policies: policies
            )
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
