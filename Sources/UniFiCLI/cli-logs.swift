import Arguments
import Foundation
import LogCollection
import Milieu

/// `unifi logs` reads the UDM's exported system log from the syslogger service, not from
/// the UDM: the UniFi integration API has no log endpoints. The UDM forwards its log
/// (Integration → System Logging / SIEM) to syslogger, which stores it and serves it over HTTP.
enum LogsCommand: RunnableArgumentCommand {
    static let name = "logs"

    static func components() throws -> [CommandComponentLowerable] {
        [
            about("Show the UDM's exported system log, as collected by syslogger. Configure with SYSLOGGER_URL and SYSLOGGER_API_KEY."),
            discussion(
                """
                This does not query the UDM. The UDM forwards its log (Integration → System Logging / SIEM, CEF over syslog) \
                to the syslogger service; this command reads syslogger's HTTP API.
                SYSLOGGER_URL is the service base, e.g. https://malinois.lan/syslogger/v1 (internal-only; LAN or VPN).
                Examples: unifi logs --since 2h · unifi logs --category Security · unifi logs --stats
                """
            ),
            opt("url", as: String.self, help: "Syslogger base URL; defaults to SYSLOGGER_URL."),
            opt("since", as: String.self, help: "Only entries newer than this: a duration (30m, 2h, 7d) or an ISO 8601 time."),
            opt("until", as: String.self, help: "Only entries older than this: a duration or an ISO 8601 time."),
            opt("category", as: String.self, help: "UniFi category, e.g. Security, System, Monitoring (field UNIFIcategory)."),
            opt("field", as: String.self, help: "Exact match on a parsed field, together with --value (e.g. --field src --value 10.60.10.147)."),
            opt("value", as: String.self, help: "Value for --field."),
            opt("contains", as: String.self, help: "Case-insensitive text match on the raw line."),
            opt("limit", as: Int.self, help: "Maximum entries, newest first (default 50, max 2000)."),
            flag("raw", negation: .none, help: "Print the raw syslog lines instead of a table."),
            flag("stats", negation: .none, help: "Show collector statistics instead of entries."),
        ]
    }

    static func run(_ invocation: ParsedInvocation) async throws {
        let client = try SysloggerClient(
            base: try invocation.value("url", as: String.self)
                ?? (try? EnvironmentExtractor.value("SYSLOGGER_URL"))
        )

        if try invocation.flag("stats") {
            let stats: CollectorStats = try await client.get("stats")
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
            FileHandle.standardOutput.write(try encoder.encode(stats))
            print("")
            return
        }

        let category = try invocation.value("category", as: String.self)
        let field = try invocation.value("field", as: String.self)
        guard category == nil || field == nil else {
            throw LogsFailure.conflictingFilters
        }
        // Validated locally by the same invariant syslogger applies on decode.
        let query = try EntriesQuery(
            .init(
                since: try invocation.value("since", as: String.self).map(timestamp),
                until: try invocation.value("until", as: String.self).map(timestamp),
                contains: try invocation.value("contains", as: String.self),
                field: category == nil ? field : "UNIFIcategory",
                value: category ?? (try invocation.value("value", as: String.self)),
                limit: try invocation.value("limit", as: Int.self) ?? 50
            )
        )

        let response: EntriesResponse = try await client.post("entries", body: query)

        if try invocation.flag("raw") {
            for entry in response.entries.reversed() {
                print(entry.raw)
            }
            return
        }

        let local = DateFormatter()
        local.dateFormat = "yyyy-MM-dd HH:mm:ss"

        printTable(
            ["TIME", "SEV", "CATEGORY", "EVENT", "MESSAGE"],
            response.entries.reversed().map { entry in
                let received = EntriesQuery.parseDate(entry.received_at).map(local.string(from:)) ?? entry.received_at
                let category = [entry.fields["UNIFIcategory"], entry.fields["UNIFIsubCategory"]]
                    .compactMap { $0 }
                    .joined(separator: "/")
                let event = entry.cef?.name ?? entry.payload
                let message = entry.cef?["msg"] ?? entry.message
                return [
                    received,
                    entry.cef?.severity ?? entry.severity ?? "-",
                    category.isEmpty ? "-" : category,
                    event,
                    String(message.replacingOccurrences(of: "\n", with: " ").prefix(140)),
                ]
            }
        )
        if response.truncated {
            print("\n(more entries match; raise --limit or narrow with --since)")
        }
    }

    /// `30m`, `2h`, `7d`, `45s` → ISO 8601 time that long ago; anything else is passed through as ISO 8601.
    static func timestamp(_ text: String) throws -> String {
        let units: [Character: Double] = ["s": 1, "m": 60, "h": 3600, "d": 86_400]
        if let unit = text.last, let seconds = units[unit], let amount = Double(text.dropLast()), amount >= 0 {
            return ISO8601DateFormatter().string(from: Date().addingTimeInterval(-amount * seconds))
        }
        guard ISO8601DateFormatter().date(from: text) != nil else {
            throw LogsFailure.invalidTime(text)
        }
        return text
    }
}

enum LogsFailure: Error, LocalizedError {
    case missingURL
    case invalidURL(String)
    case missingKey
    case invalidTime(String)
    case conflictingFilters
    case http(Int, String)
    case invalidResponse

    var errorDescription: String? {
        switch self {
        case .missingURL:
            return "No syslogger URL. Set SYSLOGGER_URL (e.g. https://malinois.lan/syslogger/v1) or pass --url."
        case .invalidURL(let value):
            return "Invalid syslogger URL '\(value)'."
        case .missingKey:
            return "SYSLOGGER_API_KEY is not set (run with with_dev_environment)."
        case .invalidTime(let value):
            return "Invalid time '\(value)'. Use a duration like 30m, 2h, 7d, or an ISO 8601 time."
        case .conflictingFilters:
            return "Use either --category or --field, not both."
        case .http(let status, let body):
            return "syslogger returned HTTP \(status): \(body.prefix(200))"
        case .invalidResponse:
            return "syslogger returned an unexpected response."
        }
    }
}

/// Minimal client for syslogger's internal HTTP API (bearer SYSLOGGER_API_KEY).
struct SysloggerClient {
    let base: URL
    let key: String

    init(base raw: String?) throws {
        guard let raw else { throw LogsFailure.missingURL }
        let trimmed = raw.hasSuffix("/") ? String(raw.dropLast()) : raw
        guard let url = URL(string: trimmed), url.scheme == "https" || url.scheme == "http", url.host != nil else {
            throw LogsFailure.invalidURL(raw)
        }
        guard let key = try? EnvironmentExtractor.value("SYSLOGGER_API_KEY") else {
            throw LogsFailure.missingKey
        }
        self.base = url
        self.key = key
    }

    func get<Response: Decodable>(_ path: String) async throws -> Response {
        try await send(URLRequest(url: base.appendingPathComponent(path)))
    }

    func post<Body: Encodable, Response: Decodable>(_ path: String, body: Body) async throws -> Response {
        var request = URLRequest(url: base.appendingPathComponent(path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(body)
        return try await send(request)
    }

    private func send<Response: Decodable>(_ request: URLRequest) async throws -> Response {
        var request = request
        request.setValue("Bearer \(key)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw LogsFailure.invalidResponse }
        guard (200..<300).contains(http.statusCode) else {
            throw LogsFailure.http(http.statusCode, String(decoding: data, as: UTF8.self))
        }
        return try JSONDecoder().decode(Response.self, from: data)
    }
}
