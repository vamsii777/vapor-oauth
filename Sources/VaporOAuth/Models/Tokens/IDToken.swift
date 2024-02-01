import JWTKit
import Vapor

public protocol IDToken: JWTPayload {
    var jti: String { get set } // JWT ID, a unique identifier for the token
    var iss: String { get set } // Issuer
    var sub: String { get set } // Subject
    var aud: [String] { get set } // Audience
    var exp: Date { get set } // Expiration Time
    var iat: Date { get set } // Issued At
    var nonce: String? { get set } // Nonce, used in OpenID Connect
    var authTime: Date? { get set } // Authentication Time
    // Additional claims can be added as needed
}
