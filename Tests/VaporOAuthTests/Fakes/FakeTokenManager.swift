import VaporOAuth
import Foundation
import JWTKit

// Define your custom IDToken conforming struct
struct MyIDToken: VaporOAuth.IDToken {
    
    var jti: String = ""
    var iss: String = ""
    var sub: String = ""
    var aud: [String] = []
    var iat: Date = Date()
    var exp: Date = Date()
    var nonce: String? = nil
    var authTime: Date? = nil
    
    func verify(using signer: JWTKit.JWTSigner) throws {
        // Verify that the token has not expired
        try exp.verifyNotExpired()
        
        // Additional verification logic can be added here
        // For example, verifying issuer, audience, etc.
    }

}

class FakeTokenManager: TokenManager {
    
    func generateTokens(clientID: String, userID: String?, scopes: [String]?, accessTokenExpiryTime: Int, idTokenExpiryTime: Int, nonce: String?) async throws -> (VaporOAuth.AccessToken, VaporOAuth.RefreshToken, VaporOAuth.IDToken) {
        // Generate access token
        let accessToken = try generateAccessToken(clientID: clientID, userID: userID, scopes: scopes, expiryTime: accessTokenExpiryTime)
        
        // Generate refresh token
        let refreshToken = try generateAccessRefreshTokens(clientID: clientID, userID: userID, scopes: scopes, accessTokenExpiryTime: accessTokenExpiryTime).1
        
        // Generate ID token
        let idToken = try await generateIDToken(clientID: clientID, userID: userID ?? "", scopes: scopes, expiryTime: idTokenExpiryTime, nonce: nonce)
        
        return (accessToken, refreshToken, idToken)
    }
    
    func generateIDToken(clientID: String, userID: String, scopes: [String]?, expiryTime: Int, nonce: String?) async throws -> VaporOAuth.IDToken {
        // Create an instance of your IDToken conforming object and set its properties
        var idToken = MyIDToken()
        idToken.jti = "YOUR-ID-TOKEN-STRING"
        idToken.iss = "YOUR-ISSUER"
        idToken.sub = userID
        idToken.aud = [clientID]
        idToken.exp = Date().addingTimeInterval(TimeInterval(expiryTime))
        idToken.iat = Date()
        idToken.nonce = nonce
        
        return idToken
    }
    
    
    var accessTokenToReturn = "ACCESS-TOKEN-STRING"
    var refreshTokenToReturn = "REFRESH-TOKEN-STRING"
    var refreshTokens: [String: RefreshToken] = [:]
    var accessTokens: [String: AccessToken] = [:]
    var deviceCodes: [String: OAuthDeviceCode] = [:]
    var currentTime = Date()
    
    func getRefreshToken(_ refreshToken: String) -> RefreshToken? {
        return refreshTokens[refreshToken]
    }
    
    func getAccessToken(_ accessToken: String) -> AccessToken? {
        return accessTokens[accessToken]
    }
    
    func generateAccessRefreshTokens(clientID: String, userID: String?, scopes: [String]?, accessTokenExpiryTime: Int) throws -> (AccessToken, RefreshToken) {
        // Convert scopes array to a single string, separated by spaces, or nil if scopes is nil
        let scopesString = scopes?.joined(separator: " ")
        
        let accessToken = FakeAccessToken(jti: accessTokenToReturn, clientID: clientID, userID: userID, scopes: scopesString, expiryTime: currentTime.addingTimeInterval(TimeInterval(accessTokenExpiryTime)))
        let refreshToken = FakeRefreshToken(jti: refreshTokenToReturn, clientID: clientID, userID: userID, scopes: scopesString, exp: currentTime.addingTimeInterval(TimeInterval(accessTokenExpiryTime)))
        
        accessTokens[accessTokenToReturn] = accessToken
        refreshTokens[refreshTokenToReturn] = refreshToken
        
        return (accessToken, refreshToken)
    }
    
    func generateAccessToken(clientID: String, userID: String?, scopes: [String]?, expiryTime: Int) throws -> AccessToken {
        let scopesString = scopes?.joined(separator: " ")
        let accessToken = FakeAccessToken(jti: accessTokenToReturn, clientID: clientID, userID: userID, scopes: scopesString, expiryTime: currentTime.addingTimeInterval(TimeInterval(expiryTime)))
        accessTokens[accessTokenToReturn] = accessToken
        return accessToken
    }
    
    func updateRefreshToken(_ refreshToken: RefreshToken, scopes: [String]) {
        var tempRefreshToken = refreshToken
        tempRefreshToken.scopes = scopes.joined(separator: " ")
        refreshTokens[refreshToken.jti] = tempRefreshToken
    }
    
}
