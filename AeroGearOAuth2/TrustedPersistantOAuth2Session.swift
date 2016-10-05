/*
* JBoss, Home of Professional Open Source.
* Copyright Red Hat, Inc., and individual contributors
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
import Foundation

import Security
import UIKit

/**
The type of token to be saved in KeychainWrap:

- AccessToken: access token
- ExpirationDate: access token expiration date
- RefreshToken: refresh token
- RefreshExpirationDate: refresh token expiration date (used for Keycloak adapter only)
*/
public enum TokenType: String {
    case AccessToken = "AccessToken"
    case RefreshToken = "RefreshToken"
    case ExpirationDate = "ExpirationDate"
    case RefreshExpirationDate = "RefreshExpirationDate"
}

/**
A handy Keychain wrapper. It saves your OAuth2 tokens using WhenPasscodeSet ACL.
*/
open class KeychainWrap {
    
    /**
    The service id. By default set to apple bundle id.
    */
    open var serviceIdentifier: String
    
    /**
    The group id is Keychain access group which is used for sharing keychain content accross multiple apps issued from same developer. By default there is no access group.
    */
    open var groupId: String?
    
    /**
    Initialize KeychainWrapper setting default values.
    
    :param: serviceId unique service, defulated to bundleId
    :param: groupId used for SSO between app issued from same developer certificate.
    */
    public init(serviceId: String? =  Bundle.main.bundleIdentifier, groupId: String? = nil) {
        if serviceId == nil {
            self.serviceIdentifier = "unkown"
        } else {
            self.serviceIdentifier = serviceId!
        }
        self.groupId = groupId
    }
    
    /**
    Save tokens information in Keychain.
    
    :param: key usually use accountId for oauth2 module, any unique string.
    :param: tokenType type of token: access, refresh.
    :param: value string value of the token.
    */
    open func save(_ key: String, tokenType: TokenType, value: String?) -> Bool {
        // Instantiate a new default keychain query
        let keychainQuery = NSMutableDictionary()
        if let groupId = self.groupId {
            keychainQuery[kSecAttrAccessGroup as String] = groupId
        }
        keychainQuery[kSecClass as String] = kSecClassGenericPassword
        keychainQuery[kSecAttrService as String] = self.serviceIdentifier
        keychainQuery[kSecAttrAccount as String] = key + "_" + tokenType.rawValue
        
        if (value == nil) {
            let result:OSStatus = SecItemDelete(keychainQuery)
            if (result == errSecSuccess) {
                return true
            } else {
                return false
            }
        }
        
        let dataFromString: Data? = value!.data(using: String.Encoding.utf8)
        if (dataFromString == nil) {
            return false
        }
        
        keychainQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        
        // Search for the keychain items
        let statusSearch: OSStatus = SecItemCopyMatching(keychainQuery, nil)
        
        // if found update
        if (statusSearch == errSecSuccess) {
            if (dataFromString != nil) {
                let attributesToUpdate = NSMutableDictionary()
                attributesToUpdate[kSecValueData as String] = dataFromString!
                
                let statusUpdate: OSStatus = SecItemUpdate(keychainQuery, attributesToUpdate)
                if (statusUpdate != errSecSuccess) {
                    print("tokens not updated")
                    return false
                }
            } else { // revoked token or newly installed app, clear KC
                return self.resetKeychain()
            }
        } else if(statusSearch == errSecItemNotFound) { // if new, add
            keychainQuery[kSecValueData as String] = dataFromString!
            let statusAdd: OSStatus = SecItemAdd(keychainQuery, nil)
            if(statusAdd != errSecSuccess) {
                print("tokens not saved")
                return false
            }
        } else { // error case
            return false
        }
        
        return true
    }
    
    /**
    Read tokens information in Keychain. If the entry is not found return nil.
    
    :param: userAccount key of the keychain entry, usually accountId for oauth2 module.
    :param: tokenType type of token: access, refresh.
    */
    open func read(_ userAccount: String, tokenType: TokenType) -> String? {
        let keychainQuery = NSMutableDictionary()
        if let groupId = self.groupId {
            keychainQuery[kSecAttrAccessGroup as String] = groupId
        }
        keychainQuery[kSecClass as String] = kSecClassGenericPassword
        keychainQuery[kSecAttrService as String] = self.serviceIdentifier
        keychainQuery[kSecAttrAccount as String] = userAccount + "_" + tokenType.rawValue
        keychainQuery[kSecReturnData as String] = true
        keychainQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        
        var dataTypeRef: Unmanaged<AnyObject>?
        // Search for the keychain items
        let status: OSStatus = withUnsafeMutablePointer(to: &dataTypeRef) { SecItemCopyMatching(keychainQuery as CFDictionary, UnsafeMutablePointer($0)) }
        
        if (status == errSecItemNotFound) {
            print("\(tokenType.rawValue) not found")
            return nil
        } else if (status != errSecSuccess) {
            print("Error attempting to retrieve \(tokenType.rawValue) with error code \(status) ")
            return nil
        }
        
        let opaque = dataTypeRef?.toOpaque()
        var contentsOfKeychain: String?
        if let op = opaque {
            let retrievedData = Unmanaged<Data>.fromOpaque(op).takeUnretainedValue()
            
            // Convert the data retrieved from the keychain into a string
            contentsOfKeychain = NSString(data: retrievedData, encoding: String.Encoding.utf8) as? String
        } else {
            print("Nothing was retrieved from the keychain. Status code \(status)")
        }
        
        return contentsOfKeychain
    }
    
    /**
    Clear all keychain entries. Note that Keychain can only be cleared progemmatically.
    */
    open func resetKeychain() -> Bool {
        return self.deleteAllKeysForSecClass(kSecClassGenericPassword) &&
            self.deleteAllKeysForSecClass(kSecClassInternetPassword) &&
            self.deleteAllKeysForSecClass(kSecClassCertificate) &&
            self.deleteAllKeysForSecClass(kSecClassKey) &&
            self.deleteAllKeysForSecClass(kSecClassIdentity)
    }
    
    func deleteAllKeysForSecClass(_ secClass: CFTypeRef) -> Bool {
        let keychainQuery = NSMutableDictionary()
        keychainQuery[kSecClass as String] = secClass
        let result:OSStatus = SecItemDelete(keychainQuery)
        if (result == errSecSuccess) {
            return true
        } else {
            return false
        }
    }
}

/**
An OAuth2Session implementation to store OAuth2 metadata using the Keychain.
*/
open class TrustedPersistantOAuth2Session: OAuth2Session {
    
    /**
    The account id.
    */
    open var accountId: String
    
    /**
    The access token's expiration date.
    */
    open var accessTokenExpirationDate: Date? {
        get {
            let dateAsString = self.keychain.read(self.accountId, tokenType: .ExpirationDate)
            if let unwrappedDate:String = dateAsString {
                return Date(dateString: unwrappedDate)
            } else {
                return nil
            }
        }
        set(value) {
            if let unwrappedValue = value {
                self.keychain.save(self.accountId, tokenType: .ExpirationDate, value: unwrappedValue.toString())
            }
        }
    }
    
    /**
    The access token. The information is read securely from Keychain.
    */
    open var accessToken: String? {
        get {
            return self.keychain.read(self.accountId, tokenType: .AccessToken)
        }
        set(value) {
            if let unwrappedValue = value {
                self.keychain.save(self.accountId, tokenType: .AccessToken, value: unwrappedValue)
            }
        }
    }
    
    /**
    The refresh token. The information is read securely from Keychain.
    */
    open var refreshToken: String? {
        get {
            return self.keychain.read(self.accountId, tokenType: .RefreshToken)
        }
        set(value) {
            if let unwrappedValue = value {
                self.keychain.save(self.accountId, tokenType: .RefreshToken, value: unwrappedValue)
            }
        }
    }
    
    /**
    The refresh token's expiration date.
    */
    open var refreshTokenExpirationDate: Date? {
        get {
            let dateAsString = self.keychain.read(self.accountId, tokenType: .RefreshExpirationDate)
            if let unwrappedDate:String = dateAsString {
                return Date(dateString: unwrappedDate)
            } else {
                return nil
            }
        }
        set(value) {
            if let unwrappedValue = value {
                _ = self.keychain.save(self.accountId, tokenType: .RefreshExpirationDate, value: unwrappedValue.toString())
            }
        }
    }
    
    fileprivate let keychain: KeychainWrap
    
    /**
    Check validity of accessToken. return true if still valid, false when expired.
    */
    open func tokenIsNotExpired() -> Bool {
        return  self.accessTokenExpirationDate != nil ? (self.accessTokenExpirationDate!.timeIntervalSince(Date()) > 0) : true
    }
    
    /**
    Check validity of refreshToken. return true if still valid, false when expired.
    */
    open func refreshTokenIsNotExpired() -> Bool {
        return  self.refreshTokenExpirationDate != nil ? (self.refreshTokenExpirationDate!.timeIntervalSince(Date()) > 0) : true
    }
    
    /**
    Save in memory tokens information. Saving tokens allow you to refresh accesstoken transparently for the user without prompting for grant access.
    */
    open func saveAccessToken(_ accessToken: String?, refreshToken: String?, accessTokenExpiration: String?, refreshTokenExpiration: String?) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        
        let now = Date()
        if let inter = accessTokenExpiration?.doubleValue {
            self.accessTokenExpirationDate = now.addingTimeInterval(inter - 20)
        }
        if let inter = refreshTokenExpiration?.doubleValue {
            self.refreshTokenExpirationDate = now.addingTimeInterval(inter - 20)
        }
    }
    
    /**
    Clear all tokens. Method used when doing logout or revoke.
    */
    open func clearTokens() {
        self.keychain.save(self.accountId, tokenType: .ExpirationDate, value: nil)
        self.keychain.save(self.accountId, tokenType: .AccessToken, value: nil)
        self.keychain.save(self.accountId, tokenType: .RefreshToken, value: nil)
        self.keychain.save(self.accountId, tokenType: .RefreshExpirationDate, value: nil)
    }

    /**
     Clear access tokens. Method used when doing logout or revoke.
     */
    open func clearAccessTokens() {
        self.keychain.save(self.accountId, tokenType: .ExpirationDate, value: nil)
        self.keychain.save(self.accountId, tokenType: .AccessToken, value: nil)
    }

    /**
    Initialize TrustedPersistantOAuth2Session using account id. Account id is the service id used for keychain storage.
    
    :param: accountId uniqueId to identify the oauth2module
    :param: groupId used for SSO between app issued from same developer certificate.
    :param: accessToken optional parameter to initilaize the storage with initial values
    :param: accessTokenExpirationDate optional parameter to initilaize the storage with initial values
    :param: refreshToken optional parameter to initilaize the storage with initial values
    :param: refreshTokenExpirationDate optional parameter to initilaize the storage with initial values
    */
    public init(accountId: String,
        groupId: String? = nil,
        accessToken: String? = nil,
        accessTokenExpirationDate: Date? = nil,
        refreshToken: String? = nil,
        refreshTokenExpirationDate: Date? = nil) {
            self.accountId = accountId
            if groupId != nil {
                self.keychain = KeychainWrap(serviceId: groupId, groupId: groupId)
            } else {
                self.keychain = KeychainWrap()
            }
            self.accessToken = accessToken
            self.refreshToken = refreshToken
            self.accessTokenExpirationDate = accessTokenExpirationDate
            self.refreshTokenExpirationDate = refreshTokenExpirationDate
    }
}
