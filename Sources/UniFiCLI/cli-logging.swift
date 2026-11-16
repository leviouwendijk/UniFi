import Arguments
import Foundation
import UniFi
import UniFiPlanning

enum LoggingFailure: Error, LocalizedError {
    case directionRequired
    case nothingSelected
    case invalidPolicy(String)
    case unknownPolicy(UUID)
    case notUserDefined(String)

    var errorDescription: String? {
        switch self {
        case .directionRequired:
            return "Pass exactly one of --enable or --disable."
        case .nothingSelected:
            return "Select policies with --policy <uuid> (repeatable) and/or --match <text>."
        case .invalidPolicy(let value):
            return "Invalid policy id '\(value)'. Expected a UUID (see `unifi raw /sites/{site}/firewall/policies`)."
        case .unknownPolicy(let id):
            return "No policy with id \(id.uuidString.lowercased()) on this site."
        case .notUserDefined(let name):
            return "Refusing to change '\(name)': only USER_DEFINED policies can be changed."
        }
    }
}

/// Approval is the operator passing --apply after reviewing the dry run.
struct CLIApprover: UniFi.MutationApprover {
    func approve(_ review: UniFi.MutationReview) async throws {}
}

enum LoggingCommand: RunnableArgumentCommand {
    static let name = "logging"

    static func components() throws -> [CommandComponentLowerable] {
        let base: [CommandComponentLowerable] = [
            about("Enable or disable syslog logging on user-defined firewall policies. Dry run unless --apply is given."),
            opt(
                "policy",
                as: String.self,
                take: .repeating,
                help: "Policy UUID; repeat for several."
            ),
            opt(
                "match",
                as: String.self,
                help: "Select user-defined policies whose name contains this text (case-insensitive)."
            ),
            flag(
                "enable",
                negation: .none,
                help: "Turn logging on."
            ),
            flag(
                "disable",
                negation: .none,
                help: "Turn logging off."
            ),
            flag(
                "apply",
                negation: .none,
                help: "Perform the change. Without it, only show what would change."
            ),
        ]
        return base + CLIOptions.site()
    }

    static func run(_ invocation: ParsedInvocation) async throws {
        let enable = try invocation.flag("enable")
        let disable = try invocation.flag("disable")
        guard enable != disable else {
            throw LoggingFailure.directionRequired
        }
        let desired = enable
        let apply = try invocation.flag("apply")
        let ids = try invocation.values("policy", as: String.self).map { raw in
            guard let id = UUID(uuidString: raw) else { throw LoggingFailure.invalidPolicy(raw) }
            return id
        }
        let match = try invocation.value("match", as: String.self)?.lowercased()
        guard !ids.isEmpty || match != nil else {
            throw LoggingFailure.nothingSelected
        }

        let context = try CLIContext(invocation)
        let site = try await context.site(invocation)
        let snapshot = try await UniFiPlanning.Reader(client: context.client).capture(site_id: site.id)

        var selected: [UniFiPlanning.Policy] = []
        for id in ids {
            guard let policy = snapshot.policies.first(where: { $0.id == id }) else {
                throw LoggingFailure.unknownPolicy(id)
            }
            selected.append(policy)
        }
        if let match {
            selected += snapshot.policies.filter {
                $0.origin == "USER_DEFINED" && $0.name.lowercased().contains(match)
            }
        }
        var seen = Set<UUID>()
        selected = selected.filter { seen.insert($0.id).inserted }
        for policy in selected where policy.origin != "USER_DEFINED" {
            throw LoggingFailure.notUserDefined(policy.name)
        }

        let pending = selected.filter { $0.logging_enabled != desired }
        let target = desired ? "on" : "off"
        printTable(
            ["IDX", "LOGGING", "CHANGE", "NAME", "ID"],
            selected.sorted { $0.index < $1.index }.map { policy in
                [
                    String(policy.index),
                    policy.logging_enabled ? "on" : "off",
                    policy.logging_enabled == desired ? "unchanged" : "-> \(target)",
                    policy.name,
                    policy.id.uuidString.lowercased(),
                ]
            }
        )

        guard !pending.isEmpty else {
            print("\nNothing to change.")
            return
        }
        guard apply else {
            print("\nDry run: \(pending.count) polic\(pending.count == 1 ? "y" : "ies") would change. Re-run with --apply to perform it.")
            return
        }

        let plan = try UniFiPlanning.Plan.prepare(
            from: snapshot,
            changes: pending.map {
                .patch_policy_telemetry(policy_id: $0.id, logging_enabled: desired, report_flow_enabled: nil)
            }
        )
        let writer = UniFiPlanning.TelemetryWriter(client: context.client, approvedBy: CLIApprover())
        print("")
        for before in pending {
            guard let after = plan.after.policies.first(where: { $0.id == before.id }) else {
                throw LoggingFailure.unknownPolicy(before.id)
            }
            let observed = try await writer.apply(site_id: site.id, before: before, after: after)
            print("logging \(observed.logging_enabled ? "on " : "off")  verified  \(observed.name)")
        }
    }
}
