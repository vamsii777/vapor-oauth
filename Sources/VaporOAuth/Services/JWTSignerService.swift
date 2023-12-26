import JWTKit

// Define the protocol
public protocol JWTSignerService: Sendable {
    var keyManagementService: KeyManagementService { get }
    func makeJWTSigner() throws -> JWTSigner
}

// Provide a default implementation for the protocol
extension JWTSignerService {
    public func makeJWTSigner() throws -> JWTSigner {
        let privateKey = try keyManagementService.retrieveKey(identifier: keyManagementService.publicKeyIdentifier())
        return JWTSigner.rs256(key: privateKey)
    }
}
