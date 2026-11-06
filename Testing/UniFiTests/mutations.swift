import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Milieu
import UniFi

private enum MutationTestFailure: Error {
    case assertion
    case mockExhausted
    case rejected
}

private struct TestCredentials: CredentialProvider {
    func resolve(_ reference: CredentialReference) async throws -> CredentialMaterial {
        CredentialMaterial(Data("fixture-only-api-key".utf8))
    }
}

private actor ReplyTransport: UniFi.Transport {
    private let replies: [UniFi.HTTPResult]
    private var sent: [URLRequest] = []

    init(_ replies: [UniFi.HTTPResult]) {
        self.replies = replies
    }

    func send(_ request: URLRequest) async throws -> UniFi.HTTPResult {
        guard sent.count < replies.count else { throw MutationTestFailure.mockExhausted }
        let next = replies[sent.count]
        sent.append(request)
        return next
    }

    func requests() -> [URLRequest] { sent }
}

private actor CheckApprover: UniFi.MutationApprover {
    let allowed: Bool
    private var reviews: [UniFi.MutationReview] = []

    init(allowed: Bool) { self.allowed = allowed }

    func approve(_ review: UniFi.MutationReview) async throws {
        reviews.append(review)
        guard allowed else { throw MutationTestFailure.rejected }
    }

    func recorded() -> [UniFi.MutationReview] { reviews }
}

struct MutationTests {
    static func run() async throws {
        guard let gateway = URL(string: "https://controller.example:8443") else {
            throw MutationTestFailure.assertion
        }
        let siteID = UUID(uuidString: "00000000-0000-0000-0000-000000000001")!
        let zoneID = UUID(uuidString: "00000000-0000-0000-0000-000000000002")!
        let beforeZone = #"{"id":"00000000-0000-0000-0000-000000000002","name":"Old","metadata":{"origin":"USER_DEFINED"},"networkIds":[]}"#
        let afterZone = #"{"id":"00000000-0000-0000-0000-000000000002","name":"New","metadata":{"origin":"USER_DEFINED"},"networkIds":["00000000-0000-0000-0000-000000000001"]}"#
        let policy = #"{"id":"00000000-0000-0000-0000-000000000002","name":"Test","index":7,"enabled":true,"loggingEnabled":false,"reportFlowEnabled":false,"metadata":{"origin":"USER_DEFINED"},"action":{"type":"BLOCK"},"source":{"zoneId":"00000000-0000-0000-0000-000000000001"},"destination":{"zoneId":"00000000-0000-0000-0000-000000000001"},"ipProtocolScope":{"ipVersion":"IPV4_AND_IPV6"}}"#
        let afterPolicy = policy.replacingOccurrences(of: "\"loggingEnabled\":false", with: "\"loggingEnabled\":true")

        func response(_ status: Int, _ body: String) -> UniFi.HTTPResult {
            UniFi.HTTPResult(status: status, body: Data(body.utf8))
        }
        func check(_ condition: Bool) throws {
            if !condition { throw MutationTestFailure.assertion }
        }
        let draft = try UniFi.Firewall.Zone.Draft(name: "New", networkIds: [siteID])

        let createTransport = ReplyTransport([response(201, afterZone)])
        let createApprover = CheckApprover(allowed: true)
        let createClient = try UniFi.Client(gateway: gateway, credentials: TestCredentials(), transport: createTransport)
        let created = try await createClient.mutations(approvedBy: createApprover).site(siteID).firewall.zones.create(draft)
        try check(created.name == "New")
        let createRequests = await createTransport.requests()
        try check(createRequests.count == 1)
        try check(createRequests[0].httpMethod == "POST")
        try check(createRequests[0].url?.path.hasSuffix("/firewall/zones") == true)
        try check(createRequests[0].value(forHTTPHeaderField: "Content-Type") == "application/json")
        let createBody = try JSONSerialization.jsonObject(with: createRequests[0].httpBody ?? Data()) as? [String: Any]
        try check(createBody?["name"] as? String == "New")
        try check(createBody?["networkIds"] as? [String] == [siteID.uuidString])
        try check(createBody?.count == 2)

        let updateTransport = ReplyTransport([response(200, beforeZone), response(200, afterZone)])
        let updateApprover = CheckApprover(allowed: true)
        let updateClient = try UniFi.Client(gateway: gateway, credentials: TestCredentials(), transport: updateTransport)
        let updated = try await updateClient.mutations(approvedBy: updateApprover).site(siteID).firewall.zones.update(zoneID, to: draft)
        try check(updated.name == "New")
        let updateRequests = await updateTransport.requests()
        try check(updateRequests.map(\.httpMethod) == ["GET", "PUT"])
        try check(updateRequests[1].url?.path.hasSuffix("/firewall/zones/\(zoneID.uuidString.lowercased())") == true)
        let updateReviews = await updateApprover.recorded()
        if case .updateZone(_, let previous, let proposed) = updateReviews.first {
            try check(previous.name == "Old" && proposed.name == "New")
        } else {
            throw MutationTestFailure.assertion
        }

        let denyTransport = ReplyTransport([response(200, beforeZone)])
        let denyApprover = CheckApprover(allowed: false)
        let denyClient = try UniFi.Client(gateway: gateway, credentials: TestCredentials(), transport: denyTransport)
        do {
            try await denyClient.mutations(approvedBy: denyApprover).site(siteID).firewall.zones.delete(zoneID)
            throw MutationTestFailure.assertion
        } catch UniFi.Failure.mutationNotApproved {}
        try check((await denyTransport.requests()).count == 1)

        let deleteTransport = ReplyTransport([response(200, beforeZone), response(200, "")])
        let deleteApprover = CheckApprover(allowed: true)
        let deleteClient = try UniFi.Client(gateway: gateway, credentials: TestCredentials(), transport: deleteTransport)
        try await deleteClient.mutations(approvedBy: deleteApprover).site(siteID).firewall.zones.delete(zoneID)
        try check((await deleteTransport.requests()).map(\.httpMethod) == ["GET", "DELETE"])

        let patchTransport = ReplyTransport([response(200, policy), response(200, afterPolicy)])
        let patchApprover = CheckApprover(allowed: true)
        let patchClient = try UniFi.Client(gateway: gateway, credentials: TestCredentials(), transport: patchTransport)
        let patch = try UniFi.Firewall.Policy.TelemetryPatch(loggingEnabled: true)
        let patched = try await patchClient.mutations(approvedBy: patchApprover).site(siteID).firewall.policies.patchTelemetry(zoneID, to: patch)
        try check(patched.loggingEnabled)
        let patchRequests = await patchTransport.requests()
        try check(patchRequests.map(\.httpMethod) == ["GET", "PATCH"])
        let body = try JSONSerialization.jsonObject(with: patchRequests[1].httpBody ?? Data()) as? [String: Any]
        try check(body?.count == 1)
        try check(body?["loggingEnabled"] as? Bool == true)
        try check(body?["reportFlowEnabled"] == nil)
        try check(body?["action"] == nil)

        do {
            _ = try UniFi.Firewall.Policy.TelemetryPatch()
            throw MutationTestFailure.assertion
        } catch UniFi.Failure.invalidMutation {}
        do {
            _ = try UniFi.Firewall.Zone.Draft(name: " ", networkIds: [])
            throw MutationTestFailure.assertion
        } catch UniFi.Failure.invalidMutation {}
        do {
            _ = try UniFi.Firewall.Zone.Draft(name: "x", networkIds: [siteID, siteID])
            throw MutationTestFailure.assertion
        } catch UniFi.Failure.invalidMutation {}

        print("PASS UniFi approved firewall zone mutations and policy telemetry patch")
    }
}
