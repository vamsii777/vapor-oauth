import Vapor

struct TokenResponseGenerator {
    
    let jwtSignerService: JWTSignerService
    
    func createResponse(error: String, description: String, status: HTTPStatus = .badRequest) throws -> Response {
        let jsonDictionary = [
            OAuthResponseParameters.error: error,
            OAuthResponseParameters.errorDescription: description
        ]
        let json = try JSONSerialization.data(withJSONObject: jsonDictionary)
        return try createResponseForToken(status: status, jsonData: json)
    }

    func createResponse(accessToken: AccessToken, refreshToken: RefreshToken?,
                        expires: Int, scope: String?) throws -> Response {
        var jsonDictionary = [
            OAuthResponseParameters.tokenType: "bearer",
            OAuthResponseParameters.expires: expires,
            OAuthResponseParameters.accessToken: accessToken.tokenString
        ] as [String : Any]

        if let refreshToken = refreshToken {
            jsonDictionary[OAuthResponseParameters.refreshToken] = refreshToken.tokenString
        }

        if let scope = scope {
            jsonDictionary[OAuthResponseParameters.scope] = scope
        }

        let json = try JSONSerialization.data(withJSONObject: jsonDictionary)
        return try createResponseForToken(status: .ok, jsonData: json)
    }

    private func createResponseForToken(status: HTTPStatus, jsonData: Data) throws -> Response {
        let response = Response(status: status)

        response.body = .init(data: jsonData)
        response.headers.contentType = .json

        response.headers.replaceOrAdd(name: "pragma", value: "no-cache")
        response.headers.cacheControl = HTTPHeaders.CacheControl(noStore: true)

        return response
    }

    func createOpenIDConnectResponse(accessToken: AccessToken, refreshToken: RefreshToken?, idToken: IDToken, expires: Int, scope: String?) throws -> Response {
        let jwtSigner = try jwtSignerService.makeJWTSigner()

        // Sign the access token and ID token
        let accessTokenString = try jwtSigner.sign(accessToken)
        let idTokenString = try jwtSigner.sign(idToken)

        var jsonDictionary: [String: Any] = [
            OAuthResponseParameters.accessToken: accessTokenString,
            OAuthResponseParameters.idToken: idTokenString,
            OAuthResponseParameters.expiresIn: expires
        ]

        // If a refresh token is available, sign it and add it to the response
        if let refreshToken = refreshToken {
            let refreshTokenString = try jwtSigner.sign(refreshToken)
            jsonDictionary[OAuthResponseParameters.refreshToken] = refreshTokenString
        }

        if let scope = scope {
            jsonDictionary[OAuthResponseParameters.scope] = scope
        }

        let json = try JSONSerialization.data(withJSONObject: jsonDictionary)
        return try createResponseForToken(status: .ok, jsonData: json)
    }
}
