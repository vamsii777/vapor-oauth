import JWTKit
import VaporOAuth
import Foundation

class FakeJWTSignerService: JWTSignerService {
    // Provide a mock KeyManagementService
    var keyManagementService: KeyManagementService {
        FakeKeyManagementService()
    }
    
    // Optionally, override the makeJWTSigner if you need specific behavior for testing
    func makeJWTSigner() throws -> JWTSigner {
        // Return a fake JWTSigner. This could be a HS256 signer with a dummy secret.
        // Note: This is only for testing and should not be used in production.
        return JWTSigner.hs256(key: "dummySecret")
    }
    
}


