import Foundation
import Crypto // Import SwiftCrypto for SHA-256

struct CodeValidator {
    func validateCode(_ code: OAuthCode, clientID: String, redirectURI: String, codeVerifier: String?) -> Bool {
        guard code.clientID == clientID else {
            return false
        }
        
        guard code.expiryDate >= Date() else {
            return false
        }
        
        guard code.redirectURI == redirectURI else {
            return false
        }
        
        if let codeChallenge = code.codeChallenge, let codeChallengeMethod = code.codeChallengeMethod, let verifier = codeVerifier {
            return PKCEValidator.validate(codeChallenge: codeChallenge, verifier: verifier, method: code.codeChallengeMethod)
        }
        
        // If no PKCE was used (codeVerifier is nil), skip PKCE validation
        return true
    }
}
