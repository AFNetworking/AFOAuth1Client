//
//  AFOAuth1Token.h
//  Twitter iOS Example Client
//
//  Created by Stan Chang Khin Boon on 14/11/14.
//  Copyright (c) 2014 Just a Dream. All rights reserved.
//

#import <Foundation/Foundation.h>

/**
 
 */
@interface AFOAuth1Token : NSObject <NSCoding, NSCopying>

/**
 
 */
@property (readonly, nonatomic, copy) NSString *key;

/**
 
 */
@property (readonly, nonatomic, copy) NSString *secret;

/**
 
 */
@property (readonly, nonatomic, copy) NSString *session;

/**
 
 */
@property (nonatomic, copy) NSString *verifier;

/**
 
 */
@property (readonly, nonatomic, assign, getter = canBeRenewed) BOOL renewable;

/**
 
 */
@property (readonly, nonatomic, assign, getter = isExpired) BOOL expired;

/**
 
 */
@property (nonatomic, strong) NSDictionary *userInfo;

/**
 
 */
- (instancetype)initWithQueryString:(NSString *)queryString;

/**
 
 */
- (id)initWithKey:(NSString *)key
           secret:(NSString *)secret
          session:(NSString *)session
       expiration:(NSDate *)expiration
        renewable:(BOOL)canBeRenewed;

#ifdef _SECURITY_SECITEM_H_
///---------------------
/// @name Authenticating
///---------------------

/**
 Stores the specified OAuth token for a given web service identifier in the Keychain
 with the default Keychain Accessibilty of kSecAttrAccessibleWhenUnlocked.
 
 @param token The OAuth credential to be stored.
 @param identifier The service identifier associated with the specified token.
 
 @return Whether or not the credential was stored in the keychain.
 */
+ (BOOL)storeCredential:(AFOAuth1Token *)credential
         withIdentifier:(NSString *)identifier;

/**
 Stores the specified OAuth token for a given web service identifier in the Keychain.
 
 @param token The OAuth credential to be stored.
 @param identifier The service identifier associated with the specified token.
 @param securityAccessibility The Keychain security accessibility to store the credential with.
 
 @return Whether or not the credential was stored in the keychain.
 */
+ (BOOL)storeCredential:(AFOAuth1Token *)credential
         withIdentifier:(NSString *)identifier
      withAccessibility:(id)securityAccessibility;

/**
 Retrieves the OAuth credential stored with the specified service identifier from the Keychain.
 
 @param identifier The service identifier associated with the specified credential.
 
 @return The retrieved OAuth token.
 */
+ (AFOAuth1Token *)retrieveCredentialWithIdentifier:(NSString *)identifier;

/**
 Deletes the OAuth token stored with the specified service identifier from the Keychain.
 
 @param identifier The service identifier associated with the specified token.
 
 @return Whether or not the token was deleted from the keychain.
 */
+ (BOOL)deleteCredentialWithIdentifier:(NSString *)identifier;
#endif

@end
