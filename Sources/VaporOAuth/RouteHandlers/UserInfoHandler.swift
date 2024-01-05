import Vapor
import JWTKit

struct UserInfoHandler {
    let jwtSignerService: JWTSignerService
    let userManager: UserManager
    
    init(jwtSignerService: JWTSignerService, userManager: UserManager) {
        self.jwtSignerService = jwtSignerService
        self.userManager = userManager
    }
    
    func handleRequest(_ req: Request) async throws -> OAuthUser {
        guard let bearerToken = req.headers.bearerAuthorization else {
            throw Abort(.unauthorized, reason: "No bearer token provided")
        }
        
        // Create JWTSigner from JWTSignerService
        let jwtSigner = try jwtSignerService.makeJWTSigner()
        
        
        // Verify the token and extract the payload
        let accessTokenPayload = try jwtSigner.verify(bearerToken.token, as: AccessTokenPayload.self)
        
        // Safely unwrap the userID
        guard let userID = accessTokenPayload.userID else {
            throw Abort(.unauthorized, reason: "Access token does not contain a user ID")
        }
        
        // Use the unwrapped userID to retrieve the user
        guard let user = try await userManager.getUser(userID: userID) else {
            throw Abort(.internalServerError, reason: "User not found")
        }
        
        return user
    }
}

struct AccessTokenPayload: AccessToken, JWTPayload {
    let jti: String
    let clientID: String
    let userID: String?
    let scopes: [String]?
    let expiryTime: Date
    
    // Implement any necessary verification logic
    func verify(using signer: JWTSigner) throws {
        // For example, verify the expiry time
        guard expiryTime > Date() else {
            throw Abort(.unauthorized, reason: "Token expired")
        }
    }
}
