import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Milieu
import Errors
import UniFi
import UniFiPlanning

private enum PlanningCaptureFailure: Error {
    case assertion
}

private struct PlanningCaptureCredentials: CredentialProvider {
    func resolve(_ reference: CredentialReference) async throws -> CredentialMaterial {
        CredentialMaterial(Data("fixture-only-api-key".utf8))
    }
}

private actor PlanningCaptureTransport: UniFi.Transport {
    let drift: Bool
    private var calls: [URLRequest] = []

    init(drift: Bool = false) { self.drift = drift }

    func send(_ request: URLRequest) async throws -> UniFi.HTTPResult {
        guard let url = request.url,
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let offset = Int(components.queryItems?.first(where: { $0.name == "offset" })?.value ?? "")
        else { throw PlanningCaptureFailure.assertion }
        calls.append(request)
        let entries: [[String: Any]]
        let total: Int
        switch url.path {
        case let path where path.hasSuffix("/sites"):
            total = drift && offset == 25 ? 27 : 26
            let indices = offset == 0 ? Array(0..<25) : [25]
            entries = indices.map { index in
                [
                    "id": String(format: "00000000-0000-0000-0000-%012d", index + 1),
                    "name": "private-site-name-\(index)",
                    "internalReference": "site-\(index)",
                ]
            }
        case let path where path.hasSuffix("/networks"):
            total = drift && offset == 25 ? 27 : 26
            let indices = offset == 0 ? Array(0..<25) : [25]
            entries = indices.map { index in
                [
                    "id": String(format: "00000000-0000-0000-0000-%012d", index + 1),
                    "name": "Network \(index)",
                    "management": "GATEWAY",
                    "vlanId": index + 1,
                    "default": false,
                    "enabled": true,
                    "metadata": ["origin": "USER_DEFINED"],
                ]
            }
        case let path where path.hasSuffix("/firewall/zones") || path.hasSuffix("/firewall/policies"):
            total = 0
            entries = []
        default:
            throw PlanningCaptureFailure.assertion
        }
        let body = try JSONSerialization.data(withJSONObject: [
            "data": entries,
            "count": entries.count,
            "offset": offset,
            "limit": 25,
            "totalCount": total,
        ])
        return .init(status: 200, body: body)
    }

    func requests() -> [URLRequest] { calls }
}

struct PlanningCaptureTests {
    static func run() async throws {
        guard let site = UUID(uuidString: "00000000-0000-0000-0000-000000000099"),
              let gateway = URL(string: "https://controller.example:8443")
        else { throw PlanningCaptureFailure.assertion }
        let transport = PlanningCaptureTransport()
        let client = try UniFi.Client(
            gateway: gateway,
            credentials: PlanningCaptureCredentials(),
            transport: transport
        )
        let reader = UniFiPlanning.Reader(client: client)
        let sites = try await reader.list_sites()
        guard sites.count == 26,
              sites.first?.name == "private-site-name-0",
              sites.last?.id == UUID(uuidString: "00000000-0000-0000-0000-000000000026")
        else { throw PlanningCaptureFailure.assertion }
        let snapshot = try await reader.capture(site_id: site)
        guard snapshot.networks.count == 26,
              snapshot.zones.isEmpty,
              snapshot.policies.isEmpty,
              snapshot.site_id == site
        else { throw PlanningCaptureFailure.assertion }
        let requests = await transport.requests()
        guard requests.count == 6,
              requests.allSatisfy({ $0.httpMethod == "GET" }),
              requests[1].url?.query?.contains("offset=25") == true,
              requests[3].url?.query?.contains("offset=25") == true
        else { throw PlanningCaptureFailure.assertion }

        let driftTransport = PlanningCaptureTransport(drift: true)
        let driftClient = try UniFi.Client(
            gateway: gateway,
            credentials: PlanningCaptureCredentials(),
            transport: driftTransport
        )
        do {
            _ = try await UniFiPlanning.Reader(client: driftClient).list_sites()
            throw PlanningCaptureFailure.assertion
        } catch let failure as UniFiPlanning.ReadFailure {
            guard failure.stage == .sites, failure.kind == .pagination else {
                throw PlanningCaptureFailure.assertion
            }
        }
        do {
            _ = try await UniFiPlanning.Reader(client: driftClient).capture(site_id: site)
            throw PlanningCaptureFailure.assertion
        } catch let failure as UniFiPlanning.ReadFailure {
            guard failure.stage == .networks, failure.kind == .pagination else {
                throw PlanningCaptureFailure.assertion
            }
        }
        try await verifyLivePolicyShape(gateway: gateway, site: site)
        print("PASS UniFiPlanning paginated site discovery, 345-policy capture, safe decoding and page-drift rejection")
    }
}

private extension PlanningCaptureTests {
    static func verifyLivePolicyShape(gateway: URL, site: UUID) async throws {
        let transport = LivePolicyCaptureTransport(malformed: false)
        let client = try UniFi.Client(
            gateway: gateway, credentials: PlanningCaptureCredentials(), transport: transport
        )
        let snapshot = try await UniFiPlanning.Reader(client: client).capture(site_id: site)
        let request_count = await transport.requestCount()
        guard snapshot.policies.count == 345,
              snapshot.policies.allSatisfy({ $0.report_flow_enabled == nil }),
              request_count == 16
        else { throw PlanningCaptureFailure.assertion }

        let malformed = LivePolicyCaptureTransport(malformed: true)
        let invalidClient = try UniFi.Client(
            gateway: gateway, credentials: PlanningCaptureCredentials(), transport: malformed
        )
        do {
            _ = try await UniFiPlanning.Reader(client: invalidClient).capture(site_id: site)
            throw PlanningCaptureFailure.assertion
        } catch let failure as UniFiPlanning.ReadFailure {
            guard failure.stage == .policies,
                  failure.kind == .decoding,
                  failure.field == "ipVersion",
                  failure.coding_path.contains("index_0"),
                  failure.report.diagnostic.identity?.namespace == "unifi.planning",
                  !failure.description.contains("192.168.66.4"),
                  !String(describing: failure.report).contains("192.168.66.4")
            else { throw PlanningCaptureFailure.assertion }
        }
    }
}

private actor LivePolicyCaptureTransport: UniFi.Transport {
    let malformed: Bool
    private var count = 0
    private let zone = "00000000-0000-0000-0000-000000000002"

    init(malformed: Bool) { self.malformed = malformed }

    func send(_ request: URLRequest) async throws -> UniFi.HTTPResult {
        count += 1
        guard let url = request.url,
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let offset = Int(components.queryItems?.first(where: { $0.name == "offset" })?.value ?? "")
        else { throw PlanningCaptureFailure.assertion }
        let data: [[String: Any]]
        let total: Int
        switch url.path {
        case let path where path.hasSuffix("/networks"):
            total = 0
            data = []
        case let path where path.hasSuffix("/firewall/zones"):
            total = 1
            data = [["id": zone, "name": "private-zone-192.168.66.4",
                     "metadata": ["origin": "USER_DEFINED"], "networkIds": []]]
        case let path where path.hasSuffix("/firewall/policies"):
            total = 345
            data = (offset..<min(offset + 25, total)).map { index in
                let scope: [String: Any] = (malformed && index == 25)
                    ? [:] : ["ipVersion": "IPV4_AND_IPV6"]
                return [
                    "id": String(format: "00000000-0000-0000-0000-%012d", index + 2_000),
                    "name": "private-name-192.168.66.4", "index": index,
                    "enabled": true, "loggingEnabled": false,
                    "metadata": ["origin": "USER_DEFINED"],
                    "action": ["type": "BLOCK"],
                    "source": ["zoneId": zone], "destination": ["zoneId": zone],
                    "ipProtocolScope": scope,
                ]
            }
        default:
            throw PlanningCaptureFailure.assertion
        }
        let body = try JSONSerialization.data(withJSONObject: [
            "data": data, "count": data.count, "offset": offset,
            "limit": 25, "totalCount": total,
        ])
        return .init(status: 200, body: body)
    }

    func requestCount() -> Int { count }
}

