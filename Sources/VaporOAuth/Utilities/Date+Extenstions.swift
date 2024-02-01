import Foundation
import JWTKit

// Making the extension public so it can be accessed anywhere in your project
public extension Date {
    func verifyNotExpired() throws {
        if self < Date() {
            throw JWTError.claimVerificationFailure(name: "exp", reason: "Token has expired")
        }
    }
}
