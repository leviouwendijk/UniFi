import Arguments
import Foundation
import Milieu
import UniFi

enum CLIFailure: Error, LocalizedError {
    case missingGateway
    case invalidGateway(String)
    case invalidSite(String)
    case ambiguousSite([UniFi.Site.Overview])
    case noSites
    case invalidJSON

    var errorDescription: String? {
        switch self {
        case .missingGateway:
            return "No gateway configured. Set UNIFI_GATEWAY (e.g. https://unifi.lan) or pass --gateway."
        case .invalidGateway(let value):
            return "Invalid gateway '\(value)'. Expected an https URL without path, query or credentials."
        case .invalidSite(let value):
            return "Invalid site id '\(value)'. Expected a UUID (see `unifi sites`)."
        case .ambiguousSite(let sites):
            let listing = sites.map { "  \($0.id.uuidString.lowercased())  \($0.name)" }.joined(separator: "\n")
            return "Multiple sites found; pass --site or set UNIFI_SITE_ID:\n\(listing)"
        case .noSites:
            return "The gateway reports no sites."
        case .invalidJSON:
            return "The response was not valid JSON."
        }
    }
}

/// Options shared by every command.
enum CLIOptions {
    static func connection() -> [CommandComponentLowerable] {
        [
            opt(
                "gateway",
                as: String.self,
                help: "Gateway URL; defaults to UNIFI_GATEWAY."
            ),
        ]
    }

    static func site() -> [CommandComponentLowerable] {
        connection() + [
            opt(
                "site",
                as: String.self,
                help: "Site UUID; defaults to UNIFI_SITE_ID, or the only site."
            ),
        ]
    }
}

struct CLIContext {
    let client: UniFi.Client

    init(_ invocation: ParsedInvocation) throws {
        let raw = try invocation.value("gateway", as: String.self)
            ?? (try? EnvironmentExtractor.value("UNIFI_GATEWAY"))
        guard let raw else {
            throw CLIFailure.missingGateway
        }
        guard let gateway = URL(string: raw) else {
            throw CLIFailure.invalidGateway(raw)
        }
        do {
            client = try UniFi.Client.environment(gateway: gateway)
        } catch UniFi.Failure.invalidGateway {
            throw CLIFailure.invalidGateway(raw)
        }
    }

    func site(_ invocation: ParsedInvocation) async throws -> UniFi.SiteAPI {
        let raw = try invocation.value("site", as: String.self)
            ?? (try? EnvironmentExtractor.value("UNIFI_SITE_ID"))
        if let raw {
            guard let id = UUID(uuidString: raw) else {
                throw CLIFailure.invalidSite(raw)
            }
            return client.network.site(id)
        }
        let sites = try await collect { try await client.network.sites.list(page: $0) }
        switch sites.count {
        case 0:
            throw CLIFailure.noSites
        case 1:
            return client.network.site(sites[0].id)
        default:
            throw CLIFailure.ambiguousSite(sites)
        }
    }
}

/// Fetches every page of a paginated endpoint.
func collect<Element>(
    _ fetch: (UniFi.PageQuery) async throws -> UniFi.Page<Element>
) async throws -> [Element] {
    var elements: [Element] = []
    var offset = 0
    while true {
        let page = try await fetch(try UniFi.PageQuery(offset: offset, limit: 200))
        elements += page.data
        offset += page.data.count
        if page.data.isEmpty || offset >= page.totalCount {
            return elements
        }
    }
}

/// Prints rows as left-aligned, space-padded columns.
func printTable(_ header: [String], _ rows: [[String]]) {
    let all = [header] + rows
    let widths = header.indices.map { column in
        all.map { $0.indices.contains(column) ? $0[column].count : 0 }.max() ?? 0
    }
    for row in all {
        let cells = row.enumerated().map { index, cell in
            index == row.count - 1 ? cell : cell.padding(toLength: widths[index], withPad: " ", startingAt: 0)
        }
        print(cells.joined(separator: "  "))
    }
}

/// Sorts dotted IPv4 addresses numerically; anything else sorts after them.
func ipv4SortKey(_ address: String?) -> [Int] {
    guard let address else { return [Int.max] }
    let octets = address.split(separator: ".").compactMap { Int($0) }
    return octets.count == 4 ? octets : [Int.max]
}

extension UUID {
    var short: String { String(uuidString.lowercased().prefix(8)) }
}
