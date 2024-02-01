struct ScopeValidator {
    let validScopes: [String]?
    let clientRetriever: ClientRetriever

    func validateScope(clientID: String, scopes: String?) async throws {
        guard let scopeString = scopes else { return }
        let requestedScopes = scopeString.components(separatedBy: " ").map { $0.trimmingCharacters(in: .whitespaces) }

        let providerScopes = validScopes ?? []
        if !providerScopes.isEmpty {
            for scope in requestedScopes {
                guard providerScopes.contains(scope) else {
                    throw ScopeError.unknown
                }
            }
        }

        let client = try await clientRetriever.getClient(clientID: clientID)
        if let clientScopes = client?.validScopes {
            for scope in requestedScopes {
                guard clientScopes.contains(scope) else {
                    throw ScopeError.invalid
                }
            }
        }
    }
}

public enum ScopeError: Error {
    case invalid
    case unknown
}
