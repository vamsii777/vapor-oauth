import Vapor

public protocol TokenManager {
    // Generates both access and refresh tokens. Should be called after successful PKCE validation.
    func generateAccessRefreshTokens(
        clientID: String,
        userID: String?,
        scopes: [String]?,
        accessTokenExpiryTime: Int
    ) async throws -> (AccessToken, RefreshToken)

    // Generates only an access token. Should be called after successful PKCE validation.
    func generateAccessToken(
        clientID: String,
        userID: String?,
        scopes: [String]?,
        expiryTime: Int
    ) async throws -> AccessToken

    // Retrieves a refresh token by its string representation.
    func getRefreshToken(_ refreshToken: String) async throws -> RefreshToken?

    // Retrieves an access token by its string representation.
    func getAccessToken(_ accessToken: String) async throws -> AccessToken?

    // Updates a refresh token, typically to change its scope.
    func updateRefreshToken(_ refreshToken: RefreshToken, scopes: [String]) async throws
}
