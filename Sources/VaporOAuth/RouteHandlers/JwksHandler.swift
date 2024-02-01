import Vapor
import JWTKit

struct JwksHandler {
    
    let keyManagementService: KeyManagementService
    
    init(keyManagementService: KeyManagementService) {
        self.keyManagementService = keyManagementService
    }
    
    func handleRequest(_ req: Request) async throws -> JWKS {
        let publicJWKs = try await getPublicJWKs()
        let jwks = JWKS(keys: publicJWKs)
        return jwks
    }
    
    private func getPublicJWKs() async throws -> [JWK] {
        // Retrieve your public RSA keys using the KeyManagementService
        let publicKey = try await keyManagementService.retrieveKey(identifier: keyManagementService.publicKeyIdentifier(), keyType: .public)
        // Convert the RSA public key to JWK format
        let jwk = try keyManagementService.convertToJWK(publicKey)
        return jwk
    }
}
