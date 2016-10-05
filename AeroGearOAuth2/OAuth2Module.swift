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
import AeroGearHttp

#if os(iOS)
import UIKit
import SafariServices
#endif

/**
Notification constants emitted during oauth authorization flow.
*/
public let AGAppLaunchedWithURLNotification = "AGAppLaunchedWithURLNotification"
public let AGAppDidBecomeActiveNotification = "AGAppDidBecomeActiveNotification"
public let AGAuthzErrorDomain = "AGAuthzErrorDomain"

/**
 The current state that this module is in.
 
 - AuthorizationStatePendingExternalApproval: the module is waiting external approval.
 - AuthorizationStateApproved: the oauth flow has been approved.
 - AuthorizationStateUnknown: the oauth flow is in unknown state (e.g. user clicked cancel).
 */
enum AuthorizationState {
    case authorizationStatePendingExternalApproval
    case authorizationStateApproved
    case authorizationStateUnknown
}

/**
 Parent class of any OAuth2 module implementing generic OAuth2 authorization flow.
 */
open class OAuth2Module: AuthzModule {
    let config: Config
    var http: Http
    
    var oauth2Session: OAuth2Session
    var applicationLaunchNotificationObserver: NSObjectProtocol?
    var applicationDidBecomeActiveNotificationObserver: NSObjectProtocol?
    var state: AuthorizationState
    var isWebViewPresented = false

    open static let revokeNotification = "kRevokeNotification"
    
    /**
     Initialize an OAuth2 module.
     
     :param: config the configuration object that setups the module.
     :param: session the session that that module will be bound to.
     :param: requestSerializer the actual request serializer to use when performing requests.
     :param: responseSerializer the actual response serializer to use upon receiving a response.
     
     :returns: the newly initialized OAuth2Module.
     */
    public required init(config: Config, session: OAuth2Session? = nil, requestSerializer: RequestSerializer = HttpRequestSerializer(), responseSerializer: ResponseSerializer = JsonResponseSerializer()) {
        if (config.accountId == nil) {
            config.accountId = "ACCOUNT_FOR_CLIENTID_\(config.clientId)"
        }
        if (session == nil) {
            self.oauth2Session = TrustedPersistantOAuth2Session(accountId: config.accountId!)
        } else {
            self.oauth2Session = session!
        }
        
        self.config = config
        self.http = Http(baseURL: config.baseURL, requestSerializer: requestSerializer, responseSerializer:  responseSerializer)
        self.state = .authorizationStateUnknown
    }
    
    // MARK: Public API - To be overriden if necessary by OAuth2 specific adapter
    
    /**
    Request an authorization code.
    
    :param: completionHandler A block object to be executed when the request operation finishes.
    */
    open func requestAuthorizationCode(_ completionHandler: @escaping (AnyObject?, NSError?) -> Void) {
        // register with the notification system in order to be notified when the 'authorization' process completes in the
        // external browser, and the oauth code is available so that we can then proceed to request the 'access_token'
        // from the server.
        if applicationLaunchNotificationObserver == nil {
            applicationLaunchNotificationObserver = NotificationCenter.default.addObserver(forName: NSNotification.Name(rawValue: AGAppLaunchedWithURLNotification), object: nil, queue: nil, using: { (notification: Notification!) -> Void in
                #if os(iOS)
                self.extractCode(notification, completionHandler: completionHandler)
                if self.isWebViewPresented {
                    UIApplication.shared.keyWindow?.rootViewController?.dismiss(animated: true, completion: nil)
                }
                #endif
            })
        }
        
        // register to receive notification when the application becomes active so we
        // can clear any pending authorization requests which are not completed properly,
        // that is a user switched into the app without Accepting or Cancelling the authorization
        // request in the external browser process.
        if applicationDidBecomeActiveNotificationObserver == nil {
            applicationDidBecomeActiveNotificationObserver = NotificationCenter.default.addObserver(forName: NSNotification.Name(rawValue: AGAppDidBecomeActiveNotification), object:nil, queue:nil, using: { (note: Notification!) -> Void in
                // check the state
                if (self.state == .authorizationStatePendingExternalApproval) {
                    // unregister
                    self.stopObserving()
                    // ..and update state
                    self.state = .authorizationStateUnknown;
                }
            })
        }
        
        // update state to 'Pending'
        self.state = .authorizationStatePendingExternalApproval
        
        // calculate final url
        var params = "?scope=\(config.scope)&redirect_uri=\(config.redirectURL.urlEncode())&client_id=\(config.clientId)&response_type=code"
        // add consent prompt for online_access scope http://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess
        if config.scopes.contains("offline_access") {
            params += "&prompt=consent"
        }
        
        let url = URL(string:http.calculateURL(config.baseURL, url:config.authzEndpoint).absoluteString + params)
        if let url = url {
            #if os(iOS)
            if config.isWebView {
                let webView : UIViewController
                if #available(iOS 9.0, *) {
                    webView = SFSafariViewController(url: url)
                } else {
                    webView = OAuth2WebViewController(URL: url)
                }
                UIApplication.shared.keyWindow?.rootViewController?.present(webView, animated: true, completion: { () -> Void in
                    self.isWebViewPresented = true
                })
            } else {
                UIApplication.shared.openURL(url)
            }
            #endif
        }
    }
    
    /**
     Request to refresh an access token.
     
     :param: completionHandler A block object to be executed when the request operation finishes.
     */
    open func refreshAccessToken(_ completionHandler: @escaping (AnyObject?, NSError?) -> Void) {
        if let unwrappedRefreshToken = self.oauth2Session.refreshToken {
            var paramDict: [String: String] = ["refresh_token": unwrappedRefreshToken, "client_id": config.clientId, "grant_type": "refresh_token"]
            if (config.clientSecret != nil) {
                paramDict["client_secret"] = config.clientSecret!
            }
            
            http.POST(config.refreshTokenEndpoint!, parameters: paramDict as [String : AnyObject]?, completionHandler: { (response, error) in
                if (error != nil) {
                    if (error?.code == 400 || error?.code == 401 || error?.code == 403 || error?.code == 404) {
                        self.revokeLocalAccess()
                    }
                    
                    completionHandler(nil, error)
                    return
                }
                
                if let unwrappedResponse = response as? [String: AnyObject] {
                    let accessToken: String = unwrappedResponse["access_token"] as! String
                    let expiration = unwrappedResponse["expires_in"] as! NSNumber
                    let exp: String = expiration.stringValue
                    
                    self.oauth2Session.saveAccessToken(accessToken, refreshToken: unwrappedRefreshToken, accessTokenExpiration: exp, refreshTokenExpiration: nil)
                    
                    completionHandler(unwrappedResponse["access_token"], nil);
                }
            })
        }
    }
    
    /**
     Exchange an authorization code for an access token.
     
     :param: code the 'authorization' code to exchange for an access token.
     :param: completionHandler A block object to be executed when the request operation finishes.
     */
    open func exchangeAuthorizationCodeForAccessToken(_ code: String, completionHandler: @escaping (AnyObject?, NSError?) -> Void) {
        var paramDict: [String: String] = ["code": code, "client_id": config.clientId, "redirect_uri": config.redirectURL, "grant_type":"authorization_code"]
        
        if let unwrapped = config.clientSecret {
            paramDict["client_secret"] = unwrapped
        }
        
        http.POST(config.accessTokenEndpoint, parameters: paramDict as [String : AnyObject]?, completionHandler: {(responseObject, error) in
            if (error != nil) {
                completionHandler(nil, error)
                return
            }
            
            if let unwrappedResponse = responseObject as? [String: AnyObject] {
                let accessToken: String = unwrappedResponse["access_token"] as! String
                let refreshToken: String? = unwrappedResponse["refresh_token"] as? String
                let expiration = unwrappedResponse["expires_in"] as? NSNumber
                let exp: String? = expiration?.stringValue
                // expiration for refresh token is used in Keycloak
                let expirationRefresh = unwrappedResponse["refresh_expires_in"] as? NSNumber
                let expRefresh = expirationRefresh?.stringValue
                
                self.oauth2Session.saveAccessToken(accessToken, refreshToken: refreshToken, accessTokenExpiration: exp, refreshTokenExpiration: expRefresh)
                completionHandler(accessToken as AnyObject?, nil)
            }
        })
    }
    
    /**
     Gateway to request authorization access.
     
     :param: completionHandler A block object to be executed when the request operation finishes.
     */
    open func requestAccess(_ completionHandler: @escaping (AnyObject?, NSError?) -> Void) {
        if (self.oauth2Session.accessToken != nil && self.oauth2Session.tokenIsNotExpired()) {
            // we already have a valid access token, nothing more to be done
            completionHandler(self.oauth2Session.accessToken! as AnyObject?, nil);
        } else if (self.oauth2Session.refreshToken != nil && self.oauth2Session.refreshTokenIsNotExpired()) {
            // need to refresh token
            self.refreshAccessToken(completionHandler as! (Any?, NSError?) -> Void)
        } else if (self.config.isServiceAccount) {
            self.loginClientCredentials() { (accessToken, claims, error) in
                completionHandler(accessToken, error)
            }
        } else {
            // ask for authorization code and once obtained exchange code for access token
            self.requestAuthorizationCode(completionHandler as! (Any?, NSError?) -> Void)
        }
    }
    
    /**
     Gateway to provide authentication using the Authorization Code Flow with OpenID Connect.
     
     :param: completionHandler A block object to be executed when the request operation finishes.
     */
    open func login(_ completionHandler: @escaping (Any?, OpenIDClaim?, NSError?) -> Void) {
        
        self.requestAccess { (response:Any?, error:NSError?) -> Void in
            
            if (error != nil) {
                completionHandler(nil, nil, error)
                return
            }
            var paramDict: [String: String] = [:]
            if response != nil {
                paramDict = ["access_token": response! as! String]
            }
            if let userInfoEndpoint = self.config.userInfoEndpoint {
                
                self.http.GET(userInfoEndpoint, parameters: paramDict as [String : AnyObject]?, completionHandler: {(responseObject, error) in
                    if (error != nil) {
                        completionHandler(nil, nil, error)
                        return
                    }
                    var openIDClaims: OpenIDClaim?
                    if let unwrappedResponse = responseObject as? [String: AnyObject] {
                        openIDClaims = OpenIDClaim(fromDict: unwrappedResponse)
                    }
                    completionHandler(response, openIDClaims, nil)
                })
            } else {
                completionHandler(nil, nil, NSError(domain: "OAuth2Module", code: 0, userInfo: ["OpenID Connect" : "No UserInfo endpoint available in config"]))
                return
            }
            
        }
        
    }
    
    /**
     Gateway to login with client credentials
     
     :param: completionHandler A block object to be executed when the request operation finishes.
     */
    open func loginClientCredentials(_ completionHandler: @escaping (AnyObject?, OpenIDClaim?, NSError?) -> Void) {
        
        let paramDict: [String: String] = ["client_id": config.clientId, "client_secret": config.clientSecret!, "scope": config.scope, "grant_type": "client_credentials"]
        
        http.POST(config.accessTokenEndpoint, parameters: paramDict as [String : AnyObject]?, completionHandler: { (response, error) in
            if (error != nil) {
                completionHandler(nil, nil, error)
                return
            }
            
            if let unwrappedResponse = response as? [String: AnyObject] {
                let accessToken: String = unwrappedResponse["access_token"] as! String
                let refreshToken: String? = unwrappedResponse["refresh_token"] as? String
                let expiration = unwrappedResponse["expires_in"] as? NSNumber
                let exp: String? = expiration?.stringValue
                // expiration for refresh token is used in Keycloak
                let expirationRefresh = unwrappedResponse["refresh_expires_in"] as? NSNumber
                let expRefresh = expirationRefresh?.stringValue
                
                // in Keycloak refresh token get refreshed every time you use them
                self.oauth2Session.saveAccessToken(accessToken, refreshToken: refreshToken, accessTokenExpiration: exp, refreshTokenExpiration: expRefresh)
                completionHandler(accessToken as AnyObject?,nil, nil);
            }
        })
    }
    
    /**
     Request to revoke access.
     
     :param: completionHandler A block object to be executed when the request operation finishes.
     */
    open func revokeAccess(_ completionHandler: @escaping (AnyObject?, NSError?) -> Void) {
        // return if not yet initialized
        if (self.oauth2Session.accessToken == nil) {
            return;
        }
        let paramDict:[String:String] = ["token":self.oauth2Session.accessToken!]
        
        http.POST(config.revokeTokenEndpoint!, parameters: paramDict as [String : AnyObject]?, completionHandler: { (response, error) in
            if (error != nil) {
                completionHandler(nil, error)
                return
            }
            
            self.oauth2Session.clearTokens()
            completionHandler(response, nil)
        })
    }

    open func revokeLocalAccess(_ notify: Bool) -> Void {
        self.oauth2Session.clearTokens()
        if notify {
            let notification = Notification(name: Notification.Name(rawValue: OAuth2Module.revokeNotification), object:nil, userInfo:nil)
            NotificationCenter.default.post(notification)
            
        }
    }
    
    open func revokeLocalAccess() -> Void {
        revokeLocalAccess(true)        
    }
    
    open func revokeLocalAccessToken() {
        self.oauth2Session.clearAccessTokens()
    }
    
    /**
     Return any authorization fields.
     
     
     
     :returns:  a dictionary filled with the authorization fields.
     */
    open func authorizationFields() -> [String: String]? {
        if (self.oauth2Session.accessToken == nil) {
            return nil
        } else {
            return ["Authorization":"Bearer \(self.oauth2Session.accessToken!)"]
        }
    }
    
    /**
     Returns a boolean indicating whether authorization has been granted.
     
     :returns: true if authorized, false otherwise.
     */
    open func isAuthorized() -> Bool {
        return self.oauth2Session.accessToken != nil && self.oauth2Session.tokenIsNotExpired()
    }
    
    // MARK: Internal Methods
    
    #if os(iOS)
    func extractCode(_ notification: Notification, completionHandler: @escaping (AnyObject?, NSError?) -> Void) {
      let userInfo = notification.userInfo as! [String: Any]
      let url = userInfo["\(UIApplicationLaunchOptionsKey.url)"] as? URL
        
        // extract the code from the URL
        let code = self.parametersFromQueryString(url?.query)["code"]
        // if exists perform the exchange
        if (code != nil) {
            self.exchangeAuthorizationCodeForAccessToken(code!, completionHandler: completionHandler)
            // update state
            state = .authorizationStateApproved
        } else {
            
            let error = NSError(domain:AGAuthzErrorDomain, code:0, userInfo:["NSLocalizedDescriptionKey": "User cancelled authorization."])
            completionHandler(nil, error)
        }
        // finally, unregister
        self.stopObserving()
    }
    #endif
    
    func parametersFromQueryString(_ queryString: String?) -> [String: String] {
        var parameters = [String: String]()
        if (queryString != nil) {
            let parameterScanner: Scanner = Scanner(string: queryString!)
            var name:NSString? = nil
            var value:NSString? = nil
            
            while (parameterScanner.isAtEnd != true) {
                name = nil;
                parameterScanner.scanUpTo("=", into: &name)
                parameterScanner.scanString("=", into:nil)
                
                value = nil
                parameterScanner.scanUpTo("&", into:&value)
                parameterScanner.scanString("&", into:nil)
                
                if (name != nil && value != nil) {
                    parameters[name!.replacingPercentEscapes(using: String.Encoding.utf8.rawValue)!] = value!.replacingPercentEscapes(using: String.Encoding.utf8.rawValue)
                }
            }
        }
        
        return parameters;
    }
   
    deinit {
        self.stopObserving()
    }
    
    func stopObserving() {
        // clear all observers
        if (applicationLaunchNotificationObserver != nil) {
            NotificationCenter.default.removeObserver(applicationLaunchNotificationObserver!)
            self.applicationLaunchNotificationObserver = nil;
        }
        
        if (applicationDidBecomeActiveNotificationObserver != nil) {
            NotificationCenter.default.removeObserver(applicationDidBecomeActiveNotificationObserver!)
            applicationDidBecomeActiveNotificationObserver = nil
        }
    }
}
