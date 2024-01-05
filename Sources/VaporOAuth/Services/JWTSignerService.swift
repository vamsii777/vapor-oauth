import JWTKit

// Define the protocol
public protocol JWTSignerService: Sendable {
    var keyManagementService: KeyManagementService { get }
    func makeJWTSigner() throws -> JWTSigner
}

// Provide a default implementation for the protocol
extension JWTSignerService {
    public func makeJWTSigner() throws -> JWTSigner {
        // Retrieve the identifier for the private key
        let privateKeyIdentifier = try keyManagementService.privateKeyIdentifier()
        // Retrieve the private key using the identifier
        let privateKey = try keyManagementService.retrieveKey(identifier: privateKeyIdentifier)
        // Create and return the JWT signer using the private key
        return JWTSigner.rs256(key: privateKey)
    }
}
