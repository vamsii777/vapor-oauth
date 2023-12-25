import Foundation
import Vapor
import JWTKit

public final class JWKS: Content {
    public let keys: [JWK]
    public init(keys: [JWK]) {
        self.keys = keys
    }
}
