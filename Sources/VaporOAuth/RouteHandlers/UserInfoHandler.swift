import Vapor
import JWTKit

struct UserInfoHandler {
    let jwtSignerService: JWTSignerService
    let userManager: UserManager
    let environment: Environment
    
    func handleRequest(_ req: Request) async throws -> OAuthUser {
        
        // Enforce HTTPS in production environment
        if environment == .production {
            guard req.url.scheme == "https" else {
                throw Abort(.badRequest, reason: "UserInfo endpoint requires HTTPS")
            }
        }
        
        guard let bearerToken = req.headers.bearerAuthorization else {
            throw Abort(.unauthorized, reason: "No bearer token provided")
        }
        
        // Create JWTSigner from JWTSignerService
        let jwtSigner = try await jwtSignerService.makeJWTSigner()
        
        
        // Verify the token and extract the payload
        let accessTokenPayload = try jwtSigner.verify(bearerToken.token, as: AccessTokenPayload.self)
        
        // Safely unwrap the userID
        guard let userID = accessTokenPayload.sub else {
            throw Abort(.unauthorized, reason: "Access token does not contain a user ID")
        }
        
        // Use the unwrapped userID to retrieve the user
        guard let user = try await userManager.getUser(userID: userID) else {
            throw Abort(.internalServerError, reason: "User not found")
        }
        
        return user
    }
}

struct AccessTokenPayload: JWTPayload {
    let jti: String
    let sub: String?
    let scopes: [String]?
    let exp: Date
    
    // Implement any necessary verification logic
    func verify(using signer: JWTSigner) throws {
        // For example, verify the expiry time
        guard exp > Date() else {
            throw Abort(.unauthorized, reason: "Token expired")
        }
    }
}
