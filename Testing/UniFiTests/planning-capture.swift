import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Milieu
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
        let snapshot = try await UniFiPlanning.Reader(client: client).capture(site_id: site)
        guard snapshot.networks.count == 26,
              snapshot.zones.isEmpty,
              snapshot.policies.isEmpty,
              snapshot.site_id == site
        else { throw PlanningCaptureFailure.assertion }
        let requests = await transport.requests()
        guard requests.count == 4,
              requests.allSatisfy({ $0.httpMethod == "GET" }),
              requests[1].url?.query?.contains("offset=25") == true
        else { throw PlanningCaptureFailure.assertion }

        let driftTransport = PlanningCaptureTransport(drift: true)
        let driftClient = try UniFi.Client(
            gateway: gateway,
            credentials: PlanningCaptureCredentials(),
            transport: driftTransport
        )
        do {
            _ = try await UniFiPlanning.Reader(client: driftClient).capture(site_id: site)
            throw PlanningCaptureFailure.assertion
        } catch UniFiPlanning.Failure.incomplete_page {}
        print("PASS UniFiPlanning paginated snapshot capture and page-drift rejection")
    }
}
