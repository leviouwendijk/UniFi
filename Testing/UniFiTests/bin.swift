import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Milieu
import UniFi

private enum TestFailure: Error {
    case assertion
    case missingUUID
}

private struct FixedCredentials: CredentialProvider {
    let value: String

    func resolve(_ reference: CredentialReference) async throws -> CredentialMaterial {
        CredentialMaterial(Data(value.utf8))
    }
}

private actor MockTransport: UniFi.Transport {
    let status: Int
    let body: Data
    private var requests: [URLRequest] = []

    init(status: Int = 200, json: String) {
        self.status = status
        self.body = Data(json.utf8)
    }

    func send(_ request: URLRequest) async throws -> UniFi.HTTPResult {
        requests.append(request)
        return UniFi.HTTPResult(status: status, body: body)
    }

    func lastRequest() -> URLRequest? { requests.last }
}

@main
struct UniFiTests {
    static func main() async throws {
        let siteID = try id("00000000-0000-0000-0000-000000000001")
        let recordID = try id("00000000-0000-0000-0000-000000000002")
        let key = "fixture-only-api-key"
        guard let gateway = URL(string: "https://controller.example:8443") else {
            throw TestFailure.assertion
        }
        let credentials = FixedCredentials(value: key)

        let sites = MockTransport(json: #"{"data":[{"id":"00000000-0000-0000-0000-000000000001","name":"Default","internalReference":"default"}],"count":1,"offset":0,"limit":25,"totalCount":1}"#)
        let client = try UniFi.Client(gateway: gateway, credentials: credentials, transport: sites)
        let sitePage = try await client.network.sites.list()
        try check(sitePage.data.first?.id == siteID)
        try check(sitePage.totalCount == 1)
        let siteRequest = await sites.lastRequest()
        try check(siteRequest?.httpMethod == "GET")
        try check(siteRequest?.value(forHTTPHeaderField: "X-API-KEY") == key)
        try check(siteRequest?.url?.absoluteString == "https://controller.example:8443/proxy/network/integration/v1/sites?offset=0&limit=25")

        let networks = MockTransport(json: #"{"data":[{"id":"00000000-0000-0000-0000-000000000002","name":"Servers","management":"GATEWAY","vlanId":40,"default":false,"enabled":true,"metadata":{"origin":"USER_DEFINED"},"zoneId":"00000000-0000-0000-0000-000000000003"}],"count":1,"offset":5,"limit":10,"totalCount":20}"#)
        let netClient = try UniFi.Client(gateway: gateway, credentials: credentials, transport: networks)
        let netPage = try await netClient.network.site(siteID).networks.list(page: .init(offset: 5, limit: 10))
        try check(netPage.data.first?.vlanId == 40)
        try check(netPage.data.first?.management == "GATEWAY")
        try check((await networks.lastRequest())?.url?.absoluteString.contains("/sites/\(siteID.uuidString.lowercased())/networks?offset=5&limit=10") == true)

        let zoneJSON = #"{"id":"00000000-0000-0000-0000-000000000002","metadata":{"origin":"USER_DEFINED"},"name":"Trusted","networkIds":["00000000-0000-0000-0000-000000000001"]}"#
        let zones = MockTransport(json: zoneJSON)
        let zoneClient = try UniFi.Client(gateway: gateway, credentials: credentials, transport: zones)
        let zone = try await zoneClient.network.site(siteID).firewall.zones.get(recordID)
        try check(zone.networkIds == [siteID])
        try check((await zones.lastRequest())?.url?.path.hasSuffix("/firewall/zones/\(recordID.uuidString.lowercased())") == true)

        let policyJSON = #"{"id":"00000000-0000-0000-0000-000000000002","name":"Deny cross VLAN","index":7,"enabled":true,"loggingEnabled":false,"reportFlowEnabled":true,"metadata":{"origin":"USER_DEFINED"},"action":{"type":"BLOCK"},"source":{"zoneId":"00000000-0000-0000-0000-000000000001"},"destination":{"zoneId":"00000000-0000-0000-0000-000000000001"},"ipProtocolScope":{"ipVersion":"IPV4_AND_IPV6"}}"#
        let policies = MockTransport(json: #"{"data": ["# + policyJSON + #"], "count": 1, "offset":0,"limit":25,"totalCount":1}"#)
        let policyClient = try UniFi.Client(gateway: gateway, credentials: credentials, transport: policies)
        let policyPage = try await policyClient.network.site(siteID).firewall.policies.list()
        try check(policyPage.data.first?.action.type == "BLOCK")
        try check(policyPage.data.first?.source.zoneId == siteID)

        let badStatus = MockTransport(status: 403, json: #"{"private":"not-for-error-text"}"#)
        let forbidden = try UniFi.Client(gateway: gateway, credentials: credentials, transport: badStatus)
        do {
            _ = try await forbidden.network.sites.list()
            throw TestFailure.assertion
        } catch UniFi.Failure.httpStatus(let status) {
            try check(status == 403)
        }

        do {
            _ = try UniFi.PageQuery(offset: -1, limit: 25)
            throw TestFailure.assertion
        } catch UniFi.Failure.invalidPage {}

        guard let insecure = URL(string: "http://controller.example") else { throw TestFailure.assertion }
        do {
            _ = try UniFi.Client(gateway: insecure, credentials: credentials)
            throw TestFailure.assertion
        } catch UniFi.Failure.invalidGateway {}

        do {
            _ = try UniFi.APIKey("bad\nkey")
            throw TestFailure.assertion
        } catch UniFi.Failure.invalidCredential {}
        let secret = try UniFi.APIKey(key)
        try check(!String(reflecting: secret).contains(key))

        try await MutationTests.run()
        try PlanningTests.run()
        try await PlanningCaptureTests.run()
        print("PASS UniFi typed read-only SDK")
    }

    static func id(_ raw: String) throws -> UUID {
        guard let value = UUID(uuidString: raw) else { throw TestFailure.missingUUID }
        return value
    }

    static func check(_ value: Bool) throws {
        if !value { throw TestFailure.assertion }
    }
}
