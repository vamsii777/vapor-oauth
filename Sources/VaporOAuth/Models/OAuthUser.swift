import Vapor

public struct OAuthUser: Authenticatable, Content {
    public var id: String?
    public let username: String
    public let emailAddress: String?
    public var password: String

    // OpenID Connect specific attributes
    public var name: String?
    public var givenName: String?
    public var familyName: String?
    public var middleName: String?
    public var nickname: String?
    public var preferredUserName: String?
    public var profile: String?
    public var picture: String?
    public var website: String?
    public var emailVerified: Bool?
    public var gender: String?
    public var birthdate: String?
    public var zoneinfo: String?
    public var locale: String?
    public var phoneNumber: String?
    public var phoneNumberVerified: Bool?
    public var address: Address?
    public var extend: [String: String]?
    public var updatedAt: Date?

    public init(userID: String? = nil, username: String, emailAddress: String?, password: String,
                name: String? = nil, givenName: String? = nil, familyName: String? = nil, middleName: String? = nil,
                nickname: String? = nil, preferredUserName: String? = nil, profile: String? = nil, picture: String? = nil, 
                website: String? = nil, emailVerified: Bool? = nil, gender: String? = nil, birthdate: String? = nil, 
                zoneinfo: String? = nil, locale: String? = nil, phoneNumber: String? = nil, phoneNumberVerified: Bool? = nil, 
                address: Address? = nil, extend: [String: String]? = nil, updatedAt: Date? = nil) {
        self.id = userID
        self.username = username
        self.emailAddress = emailAddress
        self.password = password
        self.name = name
        self.givenName = givenName
        self.familyName = familyName
        self.middleName = middleName
        self.nickname = nickname
        self.preferredUserName = preferredUserName
        self.profile = profile
        self.picture = picture
        self.website = website
        self.emailVerified = emailVerified
        self.gender = gender
        self.birthdate = birthdate
        self.zoneinfo = zoneinfo
        self.locale = locale
        self.phoneNumber = phoneNumber
        self.phoneNumberVerified = phoneNumberVerified
        self.address = address
        self.extend = extend
        self.updatedAt = updatedAt
    }
}

public struct Address: Content {
    public var formatted: String?
    public var streetAddress: String?
    public var locality: String?
    public var region: String?
    public var postalCode: String?
    public var country: String?

    public init(formatted: String? = nil, streetAddress: String? = nil, locality: String? = nil,
                region: String? = nil, postalCode: String? = nil, country: String? = nil) {
        self.formatted = formatted
        self.streetAddress = streetAddress
        self.locality = locality
        self.region = region
        self.postalCode = postalCode
        self.country = country
    }
}