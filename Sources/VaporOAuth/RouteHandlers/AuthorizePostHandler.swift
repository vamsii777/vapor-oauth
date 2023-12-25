import Vapor

struct AuthorizePostRequest {
    let user: OAuthUser
    let userID: String
    let redirectURIBaseString: String
    let approveApplication: Bool
    let clientID: String
    let responseType: String
    let csrfToken: String
    let scopes: [String]?
    let codeChallenge: String?
    let codeChallengeMethod: String?
    let nonce: String?  // OpenID Connect specific
}

struct AuthorizePostHandler {
    
    let tokenManager: TokenManager
    let codeManager: CodeManager
    let clientValidator: ClientValidator
    
    func handleRequest(request: Request) async throws -> Response {
        let requestObject = try validateAuthPostRequest(request)
        var redirectURI = requestObject.redirectURIBaseString
        
        do {
            try await clientValidator.validateClient(clientID: requestObject.clientID, responseType: requestObject.responseType,
                                                     redirectURI: requestObject.redirectURIBaseString, scopes: requestObject.scopes)
        } catch is AbortError {
            throw Abort(.forbidden)
        } catch {
            throw Abort(.badRequest)
        }
        
        guard request.session.data[SessionData.csrfToken] == requestObject.csrfToken else {
            throw Abort(.badRequest)
        }
        
        // OpenID Connect specific: Ensure 'openid' scope is included
        guard (requestObject.scopes?.contains("openid") ?? false) || requestObject.responseType.contains(ResponseType.idToken) else {
            throw Abort(.badRequest, reason: "OpenID Connect flow requires 'openid' scope")
        }
        
        
        if requestObject.approveApplication {
            switch requestObject.responseType {
            case ResponseType.token:
                let accessToken = try await tokenManager.generateAccessToken(
                    clientID: requestObject.clientID,
                    userID: requestObject.userID,
                    scopes: requestObject.scopes,
                    expiryTime: 3600
                )
                redirectURI += "#token_type=bearer&access_token=\(accessToken.tokenString)&expires_in=3600"
                
            case ResponseType.code:
                let generatedCode = try await codeManager.generateCode(
                    userID: requestObject.userID,
                    clientID: requestObject.clientID,
                    redirectURI: requestObject.redirectURIBaseString,
                    scopes: requestObject.scopes,
                    codeChallenge: requestObject.codeChallenge,
                    codeChallengeMethod: requestObject.codeChallengeMethod
                )
                redirectURI += "?code=\(generatedCode)"
                
            case ResponseType.idToken:
                
                guard let nonce = requestObject.nonce else {
                    throw Abort(.badRequest, reason: "Nonce is required for OpenID Connect id_token response type")
                }
                
                let idToken = try await tokenManager.generateIDToken(
                    clientID: requestObject.clientID,
                    userID: requestObject.userID,
                    scopes: requestObject.scopes,
                    expiryTime: 3600,
                    nonce: requestObject.nonce
                )
                redirectURI += "#id_token=\(idToken.tokenString)&expires_in=3600&token_type=bearer"
                
            case ResponseType.idToken, ResponseType.tokenAndIdToken:
                
                guard let nonce = requestObject.nonce else {
                    throw Abort(.badRequest, reason: "Nonce is required for OpenID Connect id_token response type")
                }
                // Hybrid Flow: Generate both access token and ID token
                let accessToken = try await tokenManager.generateAccessToken(
                    clientID: requestObject.clientID,
                    userID: requestObject.userID,
                    scopes: requestObject.scopes,
                    expiryTime: 3600
                )
                let idToken = try await tokenManager.generateIDToken(
                    clientID: requestObject.clientID,
                    userID: requestObject.userID,
                    scopes: requestObject.scopes,
                    expiryTime: 3600,
                    nonce: requestObject.nonce
                )
                redirectURI += "#access_token=\(accessToken.tokenString)&id_token=\(idToken.tokenString)&expires_in=3600&token_type=bearer"
                
            default:
                redirectURI += "?error=invalid_request&error_description=unknown+response+type"
            }
        } else {
            redirectURI += "?error=access_denied&error_description=user+denied+the+request"
        }
        
        if let requestedScopes = requestObject.scopes {
            if !requestedScopes.isEmpty {
                redirectURI += "&scope=\(requestedScopes.joined(separator: "+"))"
            }
        }
        
        if let state = try? request.query.get(String.self, at: OAuthRequestParameters.state) {
            redirectURI += "&state=\(state)"
        }
        
        return request.redirect(to: redirectURI)
    }
    
    private func validateAuthPostRequest(_ request: Request) throws -> AuthorizePostRequest {
        let user = try request.auth.require(OAuthUser.self)
        
        guard let userID = user.id else {
            throw Abort(.unauthorized)
        }
        
        guard let redirectURIBaseString: String = request.query[OAuthRequestParameters.redirectURI] else {
            throw Abort(.badRequest)
        }
        
        guard let approveApplication: Bool = request.content[OAuthRequestParameters.applicationAuthorized] else {
            throw Abort(.badRequest)
        }
        
        guard let clientID: String = request.query[OAuthRequestParameters.clientID] else {
            throw Abort(.badRequest)
        }
        
        guard let responseType: String = request.query[OAuthRequestParameters.responseType] else {
            throw Abort(.badRequest)
        }
        
        guard let csrfToken: String = request.content[OAuthRequestParameters.csrfToken] else {
            throw Abort(.badRequest)
        }
        
        let scopes: [String]?
        
        if let scopeQuery: String = request.query[OAuthRequestParameters.scope] {
            scopes = scopeQuery.components(separatedBy: " ")
        } else {
            scopes = nil
        }
        
        // Extract PKCE parameters
        let codeChallenge: String? = request.content[OAuthRequestParameters.codeChallenge]
        let codeChallengeMethod: String? = request.content[OAuthRequestParameters.codeChallengeMethod]
        
        // Extract nonce for OpenID Connect
        let nonce: String? = request.content[OAuthRequestParameters.nonce]
        
        
        return AuthorizePostRequest(
            user: user,
            userID: userID,
            redirectURIBaseString: redirectURIBaseString,
            approveApplication: approveApplication,
            clientID: clientID,
            responseType: responseType,
            csrfToken: csrfToken,
            scopes: scopes,
            codeChallenge: codeChallenge,
            codeChallengeMethod: codeChallengeMethod,
            nonce: nonce
        )
    }
    
}
