// AFOAuth1Token.m
//
// Copyright (c) 2011-2014 AFNetworking (http://afnetworking.com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import "AFOAuth1Token.h"

#import <Security/Security.h>

#import "AFOAuth1Utils.h"

static NSString * const kAFOAuth1CredentialServiceName = @"AFOAuth1CredentialService";

@interface AFOAuth1Token ()
@property (nonatomic, copy) NSString *key;
@property (nonatomic, copy) NSString *secret;
@property (nonatomic, copy) NSString *session;
@property (nonatomic, strong) NSDate *expiration;
@property (nonatomic, assign, getter = canBeRenewed) BOOL renewable;
@end

@implementation AFOAuth1Token

- (instancetype)initWithQueryString:(NSString *)queryString {
    if (!queryString || queryString.length == 0) {
        return nil;
    }
    
    NSDictionary *parameters = [AFOAuth1Utils parametersFromQueryString:queryString];
    
    if (parameters.count == 0) {
        return nil;
    }
    
    NSString *key = parameters[@"oauth_token"];
    NSString *secret = parameters[@"oauth_token_secret"];
    NSString *session = parameters[@"oauth_session_handle"];
    
    NSDate *expiration = nil;
    NSString *tokenDuration = parameters[@"oauth_token_duration"];
    if (tokenDuration) {
        expiration = [NSDate dateWithTimeIntervalSinceNow:[tokenDuration doubleValue]];
    }
    
    BOOL canBeRenewed = NO;
    NSString *tokenRenewable = parameters[@"oauth_token_renewable"];
    if (tokenDuration) {
        canBeRenewed = [AFOAuth1Utils isQueryStringValueTrue:tokenRenewable];
    }
    
    self = [self initWithKey:key secret:secret session:session expiration:expiration renewable:canBeRenewed];
    if (!self) {
        return nil;
    }
    
    NSMutableDictionary *mutableUserInfo = [parameters mutableCopy];
    [mutableUserInfo removeObjectsForKeys:@[ @"oauth_token", @"oauth_token_secret", @"oauth_session_handle", @"oauth_token_duration", @"oauth_token_renewable" ]];
    
    if (mutableUserInfo.count > 0) {
        self.userInfo = [mutableUserInfo copy];
    }
    
    return self;
}

- (instancetype)initWithKey:(NSString *)key
                     secret:(NSString *)secret
                    session:(NSString *)session
                 expiration:(NSDate *)expiration
                  renewable:(BOOL)canBeRenewed {
    NSParameterAssert(key);
    NSParameterAssert(secret);
    
    self = [super init];
    if (!self) {
        return nil;
    }
    
    _key = key;
    _secret = secret;
    _session = session;
    _expiration = expiration;
    _renewable = canBeRenewed;
    
    return self;
}

- (BOOL)isExpired {
    return [self.expiration compare:[NSDate date]] == NSOrderedAscending;
}

#pragma mark - NSCoding

- (id)initWithCoder:(NSCoder *)decoder {
    self = [super init];
    if (!self) {
        return nil;
    }
    
    _key = [decoder decodeObjectForKey:NSStringFromSelector(@selector(key))];
    _secret = [decoder decodeObjectForKey:NSStringFromSelector(@selector(secret))];
    _session = [decoder decodeObjectForKey:NSStringFromSelector(@selector(session))];
    _verifier = [decoder decodeObjectForKey:NSStringFromSelector(@selector(verifier))];
    _renewable = [decoder decodeBoolForKey:NSStringFromSelector(@selector(renewable))];
    _expiration = [decoder decodeObjectForKey:NSStringFromSelector(@selector(expiration))];
    _userInfo = [decoder decodeObjectForKey:NSStringFromSelector(@selector(userInfo))];
    
    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeObject:self.key forKey:NSStringFromSelector(@selector(key))];
    [coder encodeObject:self.secret forKey:NSStringFromSelector(@selector(secret))];
    [coder encodeObject:self.session forKey:NSStringFromSelector(@selector(session))];
    [coder encodeObject:self.expiration forKey:NSStringFromSelector(@selector(expiration))];
    [coder encodeBool:self.renewable forKey:NSStringFromSelector(@selector(renewable))];
    [coder encodeObject:self.verifier forKey:NSStringFromSelector(@selector(verifier))];
    [coder encodeObject:self.userInfo forKey:NSStringFromSelector(@selector(userInfo))];
}

#pragma mark - NSCopying

- (id)copyWithZone:(NSZone *)zone {
    AFOAuth1Token *copy = [[[self class] allocWithZone:zone] initWithKey:[self.key copyWithZone:zone] secret:[self.secret copyWithZone:zone] session:[self.session copyWithZone:zone] expiration:[self.expiration copyWithZone:zone] renewable:self.renewable];
    copy->_verifier = [self.verifier copyWithZone:zone];
    copy->_userInfo = [self.userInfo copyWithZone:zone];
    return copy;
}

#pragma mark -

+ (NSDictionary *)keychainQueryDictionaryWithIdentifier:(NSString *)identifier {
    return @{
             (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
             (__bridge id)kSecAttrAccount : identifier,
             (__bridge id)kSecAttrService : kAFOAuth1CredentialServiceName
             };
}

+ (AFOAuth1Token *)retrieveCredentialWithIdentifier:(NSString *)identifier {
    NSMutableDictionary *mutableQueryDictionary = [[self keychainQueryDictionaryWithIdentifier:identifier] mutableCopy];
    mutableQueryDictionary[(__bridge id)kSecReturnData] = (__bridge id)kCFBooleanTrue;
    mutableQueryDictionary[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
    
    CFDataRef result = nil;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)mutableQueryDictionary, (CFTypeRef *)&result);
    
    if (status != errSecSuccess) {
        NSLog(@"Unable to fetch credential with identifier \"%@\" (Error %li)", identifier, (long int)status);
        return nil;
    }
    
    NSData *data = (__bridge_transfer NSData *)result;
    AFOAuth1Token *credential = [NSKeyedUnarchiver unarchiveObjectWithData:data];
    
    return credential;
}

+ (BOOL)deleteCredentialWithIdentifier:(NSString *)identifier {
    NSMutableDictionary *mutableQueryDictionary = [[self keychainQueryDictionaryWithIdentifier:identifier] mutableCopy];
    
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)mutableQueryDictionary);
    
    if (status != errSecSuccess) {
        NSLog(@"Unable to delete credential with identifier \"%@\" (Error %li)", identifier, (long int)status);
    }
    
    return (status == errSecSuccess);
}

+ (BOOL)storeCredential:(AFOAuth1Token *)credential
         withIdentifier:(NSString *)identifier {
    id securityAccessibility = nil;
#if (defined(__IPHONE_OS_VERSION_MAX_ALLOWED) && __IPHONE_OS_VERSION_MAX_ALLOWED >= 43000) || (defined(__MAC_OS_X_VERSION_MAX_ALLOWED) && __MAC_OS_X_VERSION_MAX_ALLOWED >= 1090)
    securityAccessibility = (__bridge id)kSecAttrAccessibleWhenUnlocked;
#endif
    
    return [[self class] storeCredential:credential withIdentifier:identifier withAccessibility:securityAccessibility];
}

+ (BOOL)storeCredential:(AFOAuth1Token *)credential
         withIdentifier:(NSString *)identifier
      withAccessibility:(id)securityAccessibility {
    NSMutableDictionary *mutableQueryDictionary = [[self keychainQueryDictionaryWithIdentifier:identifier] mutableCopy];
    
    if (!credential) {
        return [self deleteCredentialWithIdentifier:identifier];
    }
    
    NSMutableDictionary *mutableUpdateDictionary = [[NSMutableDictionary alloc] init];
    NSData *data = [NSKeyedArchiver archivedDataWithRootObject:credential];
    mutableUpdateDictionary[(__bridge id)kSecValueData] = data;
    if (securityAccessibility) {
        [mutableUpdateDictionary setObject:securityAccessibility forKey:(__bridge id)kSecAttrAccessible];
    }
    
    OSStatus status;
    BOOL exists = !![self retrieveCredentialWithIdentifier:identifier];
    
    if (exists) {
        status = SecItemUpdate((__bridge CFDictionaryRef)mutableQueryDictionary, (__bridge CFDictionaryRef)mutableUpdateDictionary);
    } else {
        [mutableQueryDictionary addEntriesFromDictionary:mutableUpdateDictionary];
        status = SecItemAdd((__bridge CFDictionaryRef)mutableQueryDictionary, NULL);
    }
    
    if (status != errSecSuccess) {
        NSLog(@"Unable to %@ credential with identifier \"%@\" (Error %li)", exists ? @"update" : @"add", identifier, (long int)status);
    }
    
    return (status == errSecSuccess);
}

@end
