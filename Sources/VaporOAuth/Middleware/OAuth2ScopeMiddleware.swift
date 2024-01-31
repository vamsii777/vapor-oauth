import Vapor

public struct OAuth2ScopeMiddleware: AsyncMiddleware {
    let requiredScopes: String?

    public init(requiredScopes: String?) {
        self.requiredScopes = requiredScopes
    }

    public func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        // Pass the scopes as a string directly
        try await request.oAuthHelper.assertScopes(requiredScopes, request)

        return try await next.respond(to: request)
    }
}
