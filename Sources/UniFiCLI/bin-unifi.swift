import Arguments

@main
enum UniFiCLI {
    static func main() async {
        await UniFiCommand.main()
    }
}

enum UniFiCommand: ArgumentCommand {
    static let name = "unifi"

    static var children: [ArgumentCommandType] {
        [
            SitesCommand.self,
            NetworksCommand.self,
            ZonesCommand.self,
            PoliciesCommand.self,
            ClientsCommand.self,
            DevicesCommand.self,
            RawCommand.self,
            LoggingCommand.self,
            LogsCommand.self,
        ]
    }

    static func components() throws -> [CommandComponentLowerable] {
        [
            about(
                "Access to the UniFi Network integration API. Read-only, except `logging --apply`. Configure with UNIFI_GATEWAY, UNIFI_API_KEY and optionally UNIFI_SITE_ID."
            ),
        ]
    }
}
