import Foundation

public protocol DiscoveryDocument: Sendable {
    var issuer: String? { get }
    var authorizationEndpoint: String? { get }
    var tokenEndpoint: String? { get }
    var userInfoEndpoint: String? { get }
    var revocationEndpoint: String? { get }
    var introspectionEndpoint: String? { get }
    var jwksURI: String? { get }
    var registrationEndpoint: String? { get }
    var scopesSupported: [String]? { get }
    var responseTypesSupported: [String]? { get }
    var responseModesSupported: [String]? { get }
    var grantTypesSupported: [String]? { get }
    var acrValuesSupported: [String]? { get }
    var idTokenEncryptionAlgValuesSupported: [String]? { get }
    var idTokenEncryptionEncValuesSupported: [String]? { get }
    var userinfoSigningAlgValuesSupported: [String]? { get }
    var userinfoEncryptionAlgValuesSupported: [String]? { get }
    var userinfoEncryptionEncValuesSupported: [String]? { get }
    var requestObjectSigningAlgValuesSupported: [String]? { get }
    var requestObjectEncryptionAlgValuesSupported: [String]? { get }
    var requestObjectEncryptionEncValuesSupported: [String]? { get }
    var tokenEndpointAuthMethodsSupported: [String]? { get }
    var tokenEndpointAuthSigningAlgValuesSupported: [String]? { get }
    var displayValuesSupported: [String]? { get }
    var claimTypesSupported: [String]? { get }
    var claimsSupported: [String]? { get }
    var serviceDocumentation: String? { get }
    var claimsLocalesSupported: [String]? { get }
    var uiLocalesSupported: [String]? { get }
    var claimsParameterSupported: Bool? { get }
    var requestParameterSupported: Bool? { get }
    var requestUriParameterSupported: Bool? { get }
    var requireRequestUriRegistration: Bool? { get }
    var opPolicyURI: String? { get }
    var opTosURI: String? { get }
    var extend: [String: Any] { get set }
    var resourceServerRetriever: ResourceServerRetriever? { get }
    var subjectTypesSupported: [String]? { get } // Made optional to align with OAuthDiscoveryDocument
}
