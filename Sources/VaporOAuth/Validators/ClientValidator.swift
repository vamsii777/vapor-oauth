import Vapor

struct ClientValidator {
    
    let clientRetriever: ClientRetriever
    let scopeValidator: ScopeValidator
    let environment: Environment
    
    func validateClient(clientID: String, responseType: String, redirectURI: String, scopes: [String]?) async throws {
        guard let client = try await clientRetriever.getClient(clientID: clientID) else {
            throw AuthorizationError.invalidClientID
        }
        
        if client.confidentialClient ?? false {
            guard responseType == ResponseType.code else {
                throw AuthorizationError.confidentialClientTokenGrant
            }
        }
        
        guard client.validateRedirectURI(redirectURI) else {
            throw AuthorizationError.invalidRedirectURI
        }
        
        switch responseType {
        case ResponseType.code:
            guard client.allowedGrantType == .authorization else {
                throw Abort(.forbidden)
            }
        case ResponseType.token, ResponseType.idToken, ResponseType.tokenAndIdToken:
            if client.confidentialClient ?? false {
                throw AuthorizationError.confidentialClientTokenGrant
            }
            guard client.allowedGrantType == .implicit else {
                throw Abort(.forbidden)
            }
        default:
            throw AuthorizationError.invalidResponseType
        }
        
        try await scopeValidator.validateScope(clientID: clientID, scopes: scopes)
        
        let redirectURI = URI(stringLiteral: redirectURI)
        
        if environment == .production {
            if redirectURI.scheme != "https" {
                throw AuthorizationError.httpRedirectURI
            }
        }
    }
    
    
    func authenticateClient(clientID: String, clientSecret: String?, grantType: OAuthFlowType?,
                            checkConfidentialClient: Bool = false) async throws {
        guard let client = try await clientRetriever.getClient(clientID: clientID) else {
            throw ClientError.unauthorized
        }
        
        guard clientSecret == client.clientSecret else {
            throw ClientError.unauthorized
        }
        
        if let grantType = grantType {
            guard client.allowedGrantType == grantType else {
                throw Abort(.forbidden)
            }
            switch grantType {
            case .authorization:
                guard client.allowedGrantType == .authorization else { throw Abort(.forbidden) }
            case .implicit:
                guard client.allowedGrantType == .implicit else { throw Abort(.forbidden) }
            case .password:
                guard client.allowedGrantType == .password else { throw Abort(.forbidden) }
                if !client.firstParty { throw ClientError.notFirstParty }
            case .clientCredentials:
                guard client.allowedGrantType == .clientCredentials else { throw Abort(.forbidden) }
            case .refresh:
                guard client.allowedGrantType == .refresh else { throw Abort(.forbidden) }
            case .tokenIntrospection:
                guard client.allowedGrantType == .tokenIntrospection else { throw Abort(.forbidden) }
            case .deviceCode:
                guard client.allowedGrantType == .deviceCode else { throw Abort(.forbidden) }
            }
        }
        
        if checkConfidentialClient {
            guard client.confidentialClient ?? false else {
                throw ClientError.notConfidential
            }
        }
    }
}

public enum ClientError: Error {
    case unauthorized
    case notFirstParty
    case notConfidential
}
