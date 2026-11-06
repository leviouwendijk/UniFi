import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Milieu

extension UniFi {
    public enum Failure: Error, Sendable, Equatable {
        case invalidGateway
        case invalidPage
        case invalidCredential
        case credentialUnavailable
        case transportFailure
        case httpStatus(Int)
        case decodingFailure
        case encodingFailure
        case invalidMutation
        case mutationNotApproved
    }

    public struct APIKey: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
        fileprivate let value: String

        public init(_ value: String) throws {
            guard !value.isEmpty, value.utf8.allSatisfy({ $0 >= 33 && $0 <= 126 }) else {
                throw Failure.invalidCredential
            }
            self.value = value
        }

        public var description: String { "<redacted UniFi API key>" }
        public var debugDescription: String { description }
    }

    public struct HTTPResult: Sendable {
        public let status: Int
        public let body: Data

        public init(status: Int, body: Data) {
            self.status = status
            self.body = body
        }
    }

    public protocol Transport: Sendable {
        func send(_ request: URLRequest) async throws -> HTTPResult
    }

    public struct URLSessionTransport: Transport {
        private let session: URLSession

        public init() {
            let configuration = URLSessionConfiguration.ephemeral
            configuration.httpShouldSetCookies = false
            configuration.httpCookieStorage = nil
            self.session = URLSession(configuration: configuration, delegate: NoRedirect(), delegateQueue: nil)
        }

        public func send(_ request: URLRequest) async throws -> HTTPResult {
            let (body, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse else {
                throw Failure.transportFailure
            }
            return HTTPResult(status: http.statusCode, body: body)
        }
    }

    private final class NoRedirect: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
        func urlSession(
            _ session: URLSession,
            task: URLSessionTask,
            willPerformHTTPRedirection response: HTTPURLResponse,
            newRequest request: URLRequest,
            completionHandler: @escaping (URLRequest?) -> Void
        ) {
            completionHandler(nil)
        }
    }

    public struct Client: Sendable {
        let backend: Backend

        public init(
            gateway: URL,
            credentials: any CredentialProvider,
            reference: CredentialReference = CredentialReference("unifi.api_key"),
            transport: any Transport = URLSessionTransport()
        ) throws {
            guard
                gateway.scheme?.lowercased() == "https",
                gateway.host != nil,
                gateway.user == nil,
                gateway.password == nil,
                gateway.query == nil,
                gateway.fragment == nil,
                gateway.path.isEmpty || gateway.path == "/"
            else {
                throw Failure.invalidGateway
            }
            self.backend = Backend(
                gateway: gateway,
                credentials: credentials,
                reference: reference,
                transport: transport
            )
        }

        public static func environment(
            gateway: URL,
            transport: any Transport = URLSessionTransport()
        ) throws -> Self {
            let reference = CredentialReference("unifi.api_key")
            let provider = EnvironmentCredentialProvider(symbols: [reference: "UNIFI_API_KEY"])
            return try Self(gateway: gateway, credentials: provider, reference: reference, transport: transport)
        }

        public var network: NetworkAPI { NetworkAPI(backend: backend) }
    }

    struct Backend: Sendable {
        let gateway: URL
        let credentials: any CredentialProvider
        let reference: CredentialReference
        let transport: any Transport

        enum Method: String, Sendable {
            case get = "GET"
            case post = "POST"
            case put = "PUT"
            case patch = "PATCH"
            case delete = "DELETE"
        }

        func execute(
            _ method: Method,
            path: String,
            page: PageQuery? = nil,
            body: Data? = nil
        ) async throws -> HTTPResult {
            guard var components = URLComponents(url: gateway, resolvingAgainstBaseURL: false) else {
                throw Failure.invalidGateway
            }
            components.path = "/proxy/network/integration/v1" + path
            if let page {
                components.queryItems = [
                    URLQueryItem(name: "offset", value: String(page.offset)),
                    URLQueryItem(name: "limit", value: String(page.limit))
                ]
            }
            guard let url = components.url else { throw Failure.invalidGateway }

            let material: CredentialMaterial
            do {
                material = try await credentials.resolve(reference)
            } catch {
                throw Failure.credentialUnavailable
            }
            let key: APIKey
            do {
                key = try APIKey(material.utf8())
            } catch {
                throw Failure.invalidCredential
            }

            var request = URLRequest(url: url)
            request.httpMethod = method.rawValue
            request.setValue("application/json", forHTTPHeaderField: "Accept")
            request.setValue(key.value, forHTTPHeaderField: "X-API-KEY")
            if let body {
                request.httpBody = body
                request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            }
            do {
                return try await transport.send(request)
            } catch {
                throw Failure.transportFailure
            }
        }

        func get<T: Decodable & Sendable>(
            _ path: String,
            page: PageQuery? = nil,
            as type: T.Type = T.self
        ) async throws -> T {
            let result = try await execute(.get, path: path, page: page)
            guard (200..<300).contains(result.status) else {
                throw Failure.httpStatus(result.status)
            }
            do {
                return try JSONDecoder().decode(T.self, from: result.body)
            } catch {
                throw Failure.decodingFailure
            }
        }

        func write<Body: Encodable & Sendable, Response: Decodable & Sendable>(
            _ method: Method,
            path: String,
            body: Body,
            expectedStatus: Int,
            as type: Response.Type = Response.self
        ) async throws -> Response {
            let encoded: Data
            do {
                encoded = try JSONEncoder().encode(body)
            } catch {
                throw Failure.encodingFailure
            }
            let result = try await execute(method, path: path, body: encoded)
            guard result.status == expectedStatus else {
                throw Failure.httpStatus(result.status)
            }
            do {
                return try JSONDecoder().decode(Response.self, from: result.body)
            } catch {
                throw Failure.decodingFailure
            }
        }

        func remove(_ path: String) async throws {
            let result = try await execute(.delete, path: path)
            guard result.status == 200 else {
                throw Failure.httpStatus(result.status)
            }
        }
    }

    public struct PageQuery: Sendable, Equatable {
        public let offset: Int
        public let limit: Int

        public init() {
            self.offset = 0
            self.limit = 25
        }

        public init(offset: Int, limit: Int) throws {
            guard offset >= 0, limit > 0 else { throw Failure.invalidPage }
            self.offset = offset
            self.limit = limit
        }
    }

    public struct Page<Element: Decodable & Sendable>: Decodable, Sendable {
        public let data: [Element]
        public let count: Int
        public let offset: Int
        public let limit: Int
        public let totalCount: Int
    }

    public struct NetworkAPI: Sendable {
        fileprivate let backend: Backend

        public var sites: SitesAPI { SitesAPI(backend: backend) }
        public func site(_ id: UUID) -> SiteAPI { SiteAPI(backend: backend, id: id) }
    }

    public struct SitesAPI: Sendable {
        fileprivate let backend: Backend

        public func list(page: PageQuery = .init()) async throws -> Page<Site.Overview> {
            try await backend.get("/sites", page: page)
        }
    }

    public struct SiteAPI: Sendable {
        fileprivate let backend: Backend
        public let id: UUID

        public var networks: NetworksAPI { NetworksAPI(backend: backend, siteID: id) }
        public var firewall: FirewallAPI { FirewallAPI(backend: backend, siteID: id) }
    }

    public struct NetworksAPI: Sendable {
        fileprivate let backend: Backend
        public let siteID: UUID
        private var base: String { "/sites/\(siteID.uuidString.lowercased())/networks" }

        public func list(page: PageQuery = .init()) async throws -> Page<Network.Overview> {
            try await backend.get(base, page: page)
        }

        public func get(_ id: UUID) async throws -> Network.Details {
            try await backend.get("\(base)/\(id.uuidString.lowercased())")
        }
    }

    public struct FirewallAPI: Sendable {
        fileprivate let backend: Backend
        public let siteID: UUID

        public var zones: FirewallZonesAPI { FirewallZonesAPI(backend: backend, siteID: siteID) }
        public var policies: FirewallPoliciesAPI { FirewallPoliciesAPI(backend: backend, siteID: siteID) }
    }

    public struct FirewallZonesAPI: Sendable {
        fileprivate let backend: Backend
        public let siteID: UUID
        private var base: String { "/sites/\(siteID.uuidString.lowercased())/firewall/zones" }

        public func list(page: PageQuery = .init()) async throws -> Page<Firewall.Zone> {
            try await backend.get(base, page: page)
        }

        public func get(_ id: UUID) async throws -> Firewall.Zone {
            try await backend.get("\(base)/\(id.uuidString.lowercased())")
        }
    }

    public struct FirewallPoliciesAPI: Sendable {
        fileprivate let backend: Backend
        public let siteID: UUID
        private var base: String { "/sites/\(siteID.uuidString.lowercased())/firewall/policies" }

        public func list(page: PageQuery = .init()) async throws -> Page<Firewall.Policy> {
            try await backend.get(base, page: page)
        }

        public func get(_ id: UUID) async throws -> Firewall.Policy {
            try await backend.get("\(base)/\(id.uuidString.lowercased())")
        }
    }
}
