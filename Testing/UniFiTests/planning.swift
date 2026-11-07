import Difference
import Foundation
import UniFi
import UniFiPlanning

private enum PlanningTestFailure: Error {
    case assertion
}

struct PlanningTests {
    static func run() throws {
        let site = try id("00000000-0000-0000-0000-000000000001")
        let a = try id("00000000-0000-0000-0000-000000000002")
        let b = try id("00000000-0000-0000-0000-000000000003")
        let trusted = try id("00000000-0000-0000-0000-000000000004")
        let guest = try id("00000000-0000-0000-0000-000000000005")
        let policyID = try id("00000000-0000-0000-0000-000000000006")
        let networkA = try decode(UniFi.Network.Overview.self,
            #"{"id":"00000000-0000-0000-0000-000000000002","name":"10.2.1.0/24 private","management":"GATEWAY","vlanId":10,"default":false,"enabled":true,"metadata":{"origin":"USER_DEFINED"}}"#)
        let networkB = try decode(UniFi.Network.Overview.self,
            #"{"id":"00000000-0000-0000-0000-000000000003","name":"Servers","management":"GATEWAY","vlanId":20,"default":false,"enabled":true,"metadata":{"origin":"USER_DEFINED"}}"#)
        let zoneA = try decode(UniFi.Firewall.Zone.self,
            #"{"id":"00000000-0000-0000-0000-000000000004","name":"Trusted","metadata":{"origin":"USER_DEFINED"},"networkIds":["00000000-0000-0000-0000-000000000002"]}"#)
        let zoneB = try decode(UniFi.Firewall.Zone.self,
            #"{"id":"00000000-0000-0000-0000-000000000005","name":"Guest","metadata":{"origin":"USER_DEFINED"},"networkIds":[]}"#)
        let policy = try decode(UniFi.Firewall.Policy.self,
            #"{"id":"00000000-0000-0000-0000-000000000006","name":"Deny","index":4,"enabled":true,"loggingEnabled":false,"reportFlowEnabled":false,"metadata":{"origin":"USER_DEFINED"},"action":{"type":"BLOCK"},"source":{"zoneId":"00000000-0000-0000-0000-000000000004"},"destination":{"zoneId":"00000000-0000-0000-0000-000000000005"},"ipProtocolScope":{"ipVersion":"IPV4_AND_IPV6"}}"#)
        let snapshot = try UniFiPlanning.Snapshot(
            site_id: site,
            networks: [networkA, networkB],
            zones: [zoneA, zoneB],
            policies: [policy]
        )
        let plan = try UniFiPlanning.Plan.prepare(from: snapshot, changes: [
            .set_zone_networks(zone_id: trusted, network_ids: [b]),
            .patch_policy_telemetry(policy_id: policyID, logging_enabled: true, report_flow_enabled: nil),
        ])
        try check(plan.presentation.has_changes)
        try check(plan.presentation.graph?.edges.filter { $0.change != .unchanged }.count == 3)
        try check(plan.presentation.graph?.nodes.filter { $0.change == .modified }.count == 1)
        try check(!plan.presentation.changeSummary.contains("10.2.1.0"))
        let portPolicy = try decode(UniFi.Firewall.Policy.self,
            #"{"id":"00000000-0000-0000-0000-000000000006","name":"TCP 443","index":4,"enabled":true,"loggingEnabled":false,"metadata":{"origin":"USER_DEFINED"},"action":{"type":"ALLOW"},"source":{"zoneId":"00000000-0000-0000-0000-000000000004"},"destination":{"zoneId":"00000000-0000-0000-0000-000000000005","trafficFilter":{"type":"PORT","portFilter":{"type":"PORTS","matchOpposite":false,"items":[{"type":"PORT_NUMBER","value":443},{"type":"PORT_NUMBER_RANGE","start":8080,"stop":8090}]}}},"ipProtocolScope":{"ipVersion":"IPV4_AND_IPV6","protocolFilter":{"type":"NAMED_PROTOCOL","matchOpposite":false,"protocol":{"name":"tcp"}}}}"#)
        let portSnapshot = try UniFiPlanning.Snapshot(
            site_id: site, networks: [networkA, networkB],
            zones: [zoneA, zoneB], policies: [portPolicy]
        )
        try check(portSnapshot.policies[0].destination_selection?.ports?.items?.first?.value == 443)
        try check(portSnapshot.policies[0].destination_selection?.ports?.items?.last?.start == 8080)
        try check(portSnapshot.policies[0].destination_selection?.ports?.items?.last?.stop == 8090)
        try check(portSnapshot.policies[0].protocol_selection?.name == "tcp")
        try check(try JSONDecoder().decode(
            UniFiPlanning.Snapshot.self,
            from: JSONEncoder().encode(portSnapshot)
        ) == portSnapshot)
        try plan.require_fresh(snapshot)
        try plan.verify(plan.after)

        let unresolvedNetwork = try id("00000000-0000-0000-0000-000000000007")
        let unresolvedZone = try id("00000000-0000-0000-0000-000000000008")
        let partialZone = try decode(UniFi.Firewall.Zone.self,
            #"{"id":"00000000-0000-0000-0000-000000000004","name":"Trusted","metadata":{"origin":"USER_DEFINED"},"networkIds":["00000000-0000-0000-0000-000000000002","00000000-0000-0000-0000-000000000007"]}"#)
        let partialPolicy = try decode(UniFi.Firewall.Policy.self,
            #"{"id":"00000000-0000-0000-0000-000000000006","name":"Deny","index":4,"enabled":true,"loggingEnabled":false,"metadata":{"origin":"USER_DEFINED"},"action":{"type":"BLOCK"},"source":{"zoneId":"00000000-0000-0000-0000-000000000004"},"destination":{"zoneId":"00000000-0000-0000-0000-000000000008"},"ipProtocolScope":{"ipVersion":"IPV4_AND_IPV6"}}"#)
        let partial = try UniFiPlanning.Snapshot(
            site_id: site,
            networks: [networkA, networkB],
            zones: [partialZone, zoneB],
            policies: [partialPolicy]
        )
        try check(!partial.reference_complete)
        try check(partial.unresolved_network_ids == Set([unresolvedNetwork]))
        try check(partial.unresolved_zone_ids == Set([unresolvedZone]))
        try check(partial.zones[0].network_ids.contains(unresolvedNetwork))
        try check(partial.policies[0].destination_zone_id == unresolvedZone)
        try check(try partial.topology().nodes.count == 6)
        do {
            _ = try UniFiPlanning.Plan.prepare(
                from: partial,
                changes: [.patch_policy_telemetry(
                    policy_id: policyID,
                    logging_enabled: true,
                    report_flow_enabled: nil
                )]
            )
            throw PlanningTestFailure.assertion
        } catch UniFiPlanning.Failure.incomplete_snapshot {}

        let absentReporting = try decode(
            UniFi.Firewall.Policy.self,
            #"{"id":"00000000-0000-0000-0000-000000000006","name":"Deny","index":4,"enabled":true,"loggingEnabled":false,"metadata":{"origin":"USER_DEFINED"},"action":{"type":"BLOCK"},"source":{"zoneId":"00000000-0000-0000-0000-000000000004"},"destination":{"zoneId":"00000000-0000-0000-0000-000000000005"},"ipProtocolScope":{"ipVersion":"IPV4_AND_IPV6"}}"#
        )
        let unknownReporting = try UniFiPlanning.Snapshot(
            site_id: site, networks: [networkA, networkB],
            zones: [zoneA, zoneB], policies: [absentReporting]
        )
        try check(unknownReporting.policies[0].report_flow_enabled == nil)
        let reportingPlan = try UniFiPlanning.Plan.prepare(
            from: unknownReporting,
            changes: [.patch_policy_telemetry(
                policy_id: policyID, logging_enabled: nil, report_flow_enabled: false
            )]
        )
        try check(reportingPlan.before.policies[0].report_flow_enabled == nil)
        try check(reportingPlan.after.policies[0].report_flow_enabled == false)
        let restored = try JSONDecoder().decode(
            UniFiPlanning.Plan.self,
            from: JSONEncoder().encode(plan)
        )
        try check(restored == plan)
        do {
            try plan.require_fresh(plan.after)
            throw PlanningTestFailure.assertion
        } catch UniFiPlanning.Failure.stale_snapshot {}
        do {
            try plan.verify(snapshot)
            throw PlanningTestFailure.assertion
        } catch UniFiPlanning.Failure.verification_failed {}
        do {
            _ = try UniFiPlanning.Plan.prepare(from: snapshot, changes: [
                .set_zone_networks(zone_id: trusted, network_ids: [a]),
            ])
            throw PlanningTestFailure.assertion
        } catch UniFiPlanning.Failure.no_changes {}
        do {
            _ = try UniFiPlanning.Plan.prepare(from: snapshot, changes: [
                .set_zone_networks(zone_id: trusted, network_ids: [a]),
                .set_zone_networks(zone_id: trusted, network_ids: [b]),
            ])
            throw PlanningTestFailure.assertion
        } catch UniFiPlanning.Failure.duplicate_change {}
        do {
            _ = try UniFiPlanning.Plan.prepare(from: snapshot, changes: [
                .set_zone_networks(zone_id: trusted, network_ids: [guest]),
            ])
            throw PlanningTestFailure.assertion
        } catch UniFiPlanning.Failure.unknown_network(let id) {
            try check(id == guest)
        }
        print("PASS UniFiPlanning offline topology, graph diff, redacted preview, stale-state checks")
    }

    private static func id(_ value: String) throws -> UUID {
        guard let id = UUID(uuidString: value) else { throw PlanningTestFailure.assertion }
        return id
    }

    private static func decode<T: Decodable>(_ type: T.Type, _ json: String) throws -> T {
        try JSONDecoder().decode(type, from: Data(json.utf8))
    }

    private static func check(_ condition: Bool) throws {
        if !condition { throw PlanningTestFailure.assertion }
    }
}
