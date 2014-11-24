// AFOAuth1Client.m
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

#import "AFOAuth1Client.h"
#import "AFHTTPRequestOperation.h"

#import <Security/Security.h>
#import <CommonCrypto/CommonHMAC.h>

typedef void (^AFServiceProviderRequestHandlerBlock)(NSURLRequest *request);
typedef void (^AFServiceProviderRequestCompletionBlock)();

static NSString * const kAFOAuth1Version = @"1.0";
NSString * const kAFApplicationLaunchedWithURLNotification = @"kAFApplicationLaunchedWithURLNotification";
#if __IPHONE_OS_VERSION_MIN_REQUIRED
NSString * const kAFApplicationLaunchOptionsURLKey = @"UIApplicationLaunchOptionsURLKey";
#else
NSString * const kAFApplicationLaunchOptionsURLKey = @"NSApplicationLaunchOptionsURLKey";
#endif

static NSString * AFEncodeBase64WithData(NSData *data) {
    NSUInteger length = [data length];
    NSMutableData *mutableData = [NSMutableData dataWithLength:((length + 2) / 3) * 4];

    uint8_t *input = (uint8_t *)[data bytes];
    uint8_t *output = (uint8_t *)[mutableData mutableBytes];

    for (NSUInteger i = 0; i < length; i += 3) {
        NSUInteger value = 0;
        for (NSUInteger j = i; j < (i + 3); j++) {
            value <<= 8;
            if (j < length) {
                value |= (0xFF & input[j]);
            }
        }

        static uint8_t const kAFBase64EncodingTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        NSUInteger idx = (i / 3) * 4;
        output[idx + 0] = kAFBase64EncodingTable[(value >> 18) & 0x3F];
        output[idx + 1] = kAFBase64EncodingTable[(value >> 12) & 0x3F];
        output[idx + 2] = (i + 1) < length ? kAFBase64EncodingTable[(value >> 6)  & 0x3F] : '=';
        output[idx + 3] = (i + 2) < length ? kAFBase64EncodingTable[(value >> 0)  & 0x3F] : '=';
    }

    return [[NSString alloc] initWithData:mutableData encoding:NSASCIIStringEncoding];
}

static NSString * AFPercentEscapedQueryStringPairMemberFromStringWithEncoding(NSString *string, NSStringEncoding encoding) {
    static NSString * const kAFCharactersToBeEscaped = @":/?&=;+!@#$()',*";
    static NSString * const kAFCharactersToLeaveUnescaped = @"[].";

	return (__bridge_transfer NSString *)CFURLCreateStringByAddingPercentEscapes(kCFAllocatorDefault, (__bridge CFStringRef)string, (__bridge CFStringRef)kAFCharactersToLeaveUnescaped, (__bridge CFStringRef)kAFCharactersToBeEscaped, CFStringConvertNSStringEncodingToEncoding(encoding));
}

static NSDictionary * AFParametersFromQueryString(NSString *queryString) {
    NSMutableDictionary *parameters = [NSMutableDictionary dictionary];
    if (queryString) {
        NSScanner *parameterScanner = [[NSScanner alloc] initWithString:queryString];
        NSString *name = nil;
        NSString *value = nil;

        while (![parameterScanner isAtEnd]) {
            name = nil;
            [parameterScanner scanUpToString:@"=" intoString:&name];
            [parameterScanner scanString:@"=" intoString:NULL];

            value = nil;
            [parameterScanner scanUpToString:@"&" intoString:&value];
            [parameterScanner scanString:@"&" intoString:NULL];

            if (name && value) {
                parameters[[name stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding]] = [value stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
            }
        }
    }

    return parameters;
}

static inline BOOL AFQueryStringValueIsTrue(NSString *value) {
    return value && [[value lowercaseString] hasPrefix:@"t"];
}

static inline NSString * AFNounce() {
    CFUUIDRef uuid = CFUUIDCreate(NULL);
    CFStringRef string = CFUUIDCreateString(NULL, uuid);
    CFRelease(uuid);

    return (NSString *)CFBridgingRelease(string);
}

static inline NSString * NSStringFromAFOAuthSignatureMethod(AFOAuthSignatureMethod signatureMethod) {
    switch (signatureMethod) {
        case AFPlainTextSignatureMethod:
            return @"PLAINTEXT";
        case AFHMACSHA1SignatureMethod:
            return @"HMAC-SHA1";
        default:
            return nil;
    }
}

static inline NSString * AFPlainTextSignature(NSURLRequest *request, NSString *consumerSecret, NSString *tokenSecret, NSStringEncoding stringEncoding) {
    NSString *secret = tokenSecret ? tokenSecret : @"";
    NSString *signature = [NSString stringWithFormat:@"%@&%@", consumerSecret, secret];
    return signature;
}

static inline NSString * AFHMACSHA1Signature(NSURLRequest *request, NSString *consumerSecret, NSString *tokenSecret, NSStringEncoding stringEncoding) {
    NSString *secret = tokenSecret ? tokenSecret : @"";
    NSString *secretString = [NSString stringWithFormat:@"%@&%@", AFPercentEscapedQueryStringPairMemberFromStringWithEncoding(consumerSecret, stringEncoding), AFPercentEscapedQueryStringPairMemberFromStringWithEncoding(secret, stringEncoding)];
    NSData *secretStringData = [secretString dataUsingEncoding:stringEncoding];

    NSString *queryString = AFPercentEscapedQueryStringPairMemberFromStringWithEncoding([[[[[request URL] query] componentsSeparatedByString:@"&"] sortedArrayUsingSelector:@selector(compare:)] componentsJoinedByString:@"&"], stringEncoding);
    NSString *requestString = [NSString stringWithFormat:@"%@&%@&%@", [request HTTPMethod], AFPercentEscapedQueryStringPairMemberFromStringWithEncoding([[[request URL] absoluteString] componentsSeparatedByString:@"?"][0], stringEncoding), queryString];
    NSData *requestStringData = [requestString dataUsingEncoding:stringEncoding];

    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CCHmacContext cx;
    CCHmacInit(&cx, kCCHmacAlgSHA1, [secretStringData bytes], [secretStringData length]);
    CCHmacUpdate(&cx, [requestStringData bytes], [requestStringData length]);
    CCHmacFinal(&cx, digest);

    return AFEncodeBase64WithData([NSData dataWithBytes:digest length:CC_SHA1_DIGEST_LENGTH]);
}

NSString * const kAFOAuth1CredentialServiceName = @"AFOAuthCredentialService";

static NSDictionary * AFKeychainQueryDictionaryWithIdentifier(NSString *identifier) {
    return @{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
             (__bridge id)kSecAttrAccount: identifier,
             (__bridge id)kSecAttrService: kAFOAuth1CredentialServiceName
             };
}

#pragma mark -

@interface AFOAuth1Client ()
@property (readwrite, nonatomic, copy) NSString *key;
@property (readwrite, nonatomic, copy) NSString *secret;
@property (readwrite, nonatomic, strong) id applicationLaunchNotificationObserver;
@property (readwrite, nonatomic, copy) AFServiceProviderRequestHandlerBlock serviceProviderRequestHandler;
@property (readwrite, nonatomic, copy) AFServiceProviderRequestCompletionBlock serviceProviderRequestCompletion;

- (NSDictionary *)OAuthParameters;
- (NSString *)OAuthSignatureForMethod:(NSString *)method
                                 path:(NSString *)path
                           parameters:(NSDictionary *)parameters
                                token:(AFOAuth1Token *)requestToken;
- (NSString *)authorizationHeaderForMethod:(NSString*)method
                                      path:(NSString*)path
                                parameters:(NSDictionary *)parameters;
@end

@implementation AFOAuth1Client

- (id)initWithBaseURL:(NSURL *)url
                  key:(NSString *)clientID
               secret:(NSString *)secret
{
    NSParameterAssert(clientID);
    NSParameterAssert(secret);

    self = [super initWithBaseURL:url];
    if (!self) {
        return nil;
    }

    self.key = clientID;
    self.secret = secret;

    self.signatureMethod = AFHMACSHA1SignatureMethod;

    return self;
}

- (void)dealloc {
    self.applicationLaunchNotificationObserver = nil;
}

- (void)setApplicationLaunchNotificationObserver:(id)applicationLaunchNotificationObserver {
    if (_applicationLaunchNotificationObserver) {
        [[NSNotificationCenter defaultCenter] removeObserver:_applicationLaunchNotificationObserver];
    }

    [self willChangeValueForKey:@"applicationLaunchNotificationObserver"];
    _applicationLaunchNotificationObserver = applicationLaunchNotificationObserver;
    [self didChangeValueForKey:@"applicationLaunchNotificationObserver"];
}

- (NSDictionary *)OAuthParameters {
    NSMutableDictionary *parameters = [NSMutableDictionary dictionary];
    parameters[@"oauth_version"] = kAFOAuth1Version;
    parameters[@"oauth_signature_method"] = NSStringFromAFOAuthSignatureMethod(self.signatureMethod);
    parameters[@"oauth_consumer_key"] = self.key;
    parameters[@"oauth_timestamp"] = [@(floor([[NSDate date] timeIntervalSince1970])) stringValue];
    parameters[@"oauth_nonce"] = AFNounce();

    if (self.realm) {
        parameters[@"realm"] = self.realm;
    }

    return parameters;
}

- (NSString *)OAuthSignatureForMethod:(NSString *)method
                                 path:(NSString *)path
                           parameters:(NSDictionary *)parameters
                                token:(AFOAuth1Token *)token
{
    NSMutableURLRequest *request = [super requestWithMethod:@"GET" path:path parameters:parameters];
    [request setHTTPMethod:method];

    NSString *tokenSecret = token ? token.secret : nil;

    switch (self.signatureMethod) {
        case AFPlainTextSignatureMethod:
            return AFPlainTextSignature(request, self.secret, tokenSecret, self.stringEncoding);
        case AFHMACSHA1SignatureMethod:
            return AFHMACSHA1Signature(request, self.secret, tokenSecret, self.stringEncoding);
        default:
            return nil;
    }
}

- (NSString *)authorizationHeaderForMethod:(NSString *)method
                                      path:(NSString *)path
                                parameters:(NSDictionary *)parameters
{
    static NSString * const kAFOAuth1AuthorizationFormatString = @"OAuth %@";

    NSMutableDictionary *mutableParameters = parameters ? [parameters mutableCopy] : [NSMutableDictionary dictionary];
    NSMutableDictionary *mutableAuthorizationParameters = [NSMutableDictionary dictionary];

    if (self.key && self.secret) {
        [mutableAuthorizationParameters addEntriesFromDictionary:[self OAuthParameters]];
        if (self.accessToken) {
            mutableAuthorizationParameters[@"oauth_token"] = self.accessToken.key;
        }
    }

    [mutableParameters enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
        if ([key isKindOfClass:[NSString class]] && [key hasPrefix:@"oauth_"]) {
            mutableAuthorizationParameters[key] = obj;
        }
    }];

    [mutableParameters addEntriesFromDictionary:mutableAuthorizationParameters];
    mutableAuthorizationParameters[@"oauth_signature"] = [self OAuthSignatureForMethod:method path:path parameters:mutableParameters token:self.accessToken];
    
    NSArray *sortedComponents = [[AFQueryStringFromParametersWithEncoding(mutableAuthorizationParameters, self.stringEncoding) componentsSeparatedByString:@"&"] sortedArrayUsingSelector:@selector(caseInsensitiveCompare:)];
    NSMutableArray *mutableComponents = [NSMutableArray array];
    for (NSString *component in sortedComponents) {
        NSArray *subcomponents = [component componentsSeparatedByString:@"="];
        if ([subcomponents count] == 2) {
            [mutableComponents addObject:[NSString stringWithFormat:@"%@=\"%@\"", subcomponents[0], subcomponents[1]]];
        }
    }

    return [NSString stringWithFormat:kAFOAuth1AuthorizationFormatString, [mutableComponents componentsJoinedByString:@", "]];
}

#pragma mark -

- (void)authorizeUsingOAuthWithRequestTokenPath:(NSString *)requestTokenPath
                          userAuthorizationPath:(NSString *)userAuthorizationPath
                                    callbackURL:(NSURL *)callbackURL
                                accessTokenPath:(NSString *)accessTokenPath
                                   accessMethod:(NSString *)accessMethod
                                          scope:(NSString *)scope
                                        success:(void (^)(AFOAuth1Token *accessToken, id responseObject))success
                                        failure:(void (^)(NSError *error))failure
{
    [self acquireOAuthRequestTokenWithPath:requestTokenPath callbackURL:callbackURL accessMethod:(NSString *)accessMethod scope:scope success:^(AFOAuth1Token *requestToken, id responseObject) {
        __block AFOAuth1Token *currentRequestToken = requestToken;

        self.applicationLaunchNotificationObserver = [[NSNotificationCenter defaultCenter] addObserverForName:kAFApplicationLaunchedWithURLNotification object:nil queue:[NSOperationQueue mainQueue] usingBlock:^(NSNotification *notification) {
            NSURL *url = [[notification userInfo] valueForKey:kAFApplicationLaunchOptionsURLKey];

            currentRequestToken.verifier = [AFParametersFromQueryString([url query]) valueForKey:@"oauth_verifier"];

            [self acquireOAuthAccessTokenWithPath:accessTokenPath requestToken:currentRequestToken accessMethod:accessMethod success:^(AFOAuth1Token * accessToken, id responseObject) {
                if (self.serviceProviderRequestCompletion) {
                    self.serviceProviderRequestCompletion();
                }
                
                self.applicationLaunchNotificationObserver = nil;
                if (accessToken) {
                    self.accessToken = accessToken;
                    
                    if (success) {
                        success(accessToken, responseObject);
                    }
                } else {
                    if (failure) {
                        failure(nil);
                    }
                }
            } failure:^(NSError *error) {
                self.applicationLaunchNotificationObserver = nil;
                if (failure) {
                    failure(error);
                }
            }];
        }];

        NSMutableDictionary *parameters = [NSMutableDictionary dictionary];
        parameters[@"oauth_token"] = requestToken.key;

        NSMutableURLRequest *request = [super requestWithMethod:@"GET" path:userAuthorizationPath parameters:parameters];
        [request setHTTPShouldHandleCookies:NO];

        if (self.serviceProviderRequestHandler) {
            self.serviceProviderRequestHandler(request);
        } else {
#if __IPHONE_OS_VERSION_MIN_REQUIRED
            [[UIApplication sharedApplication] openURL:[request URL]];
#else
            [[NSWorkspace sharedWorkspace] openURL:[request URL]];
#endif
        }
        
    } failure:^(NSError *error) {
        if (failure) {
            failure(error);
        }
    }];
}

- (void)acquireOAuthRequestTokenWithPath:(NSString *)path
                             callbackURL:(NSURL *)callbackURL
                            accessMethod:(NSString *)accessMethod
                                   scope:(NSString *)scope
                                 success:(void (^)(AFOAuth1Token *requestToken, id responseObject))success
                                 failure:(void (^)(NSError *error))failure
{
    NSMutableDictionary *parameters = [[self OAuthParameters] mutableCopy];

    if (callbackURL) {
        parameters[@"oauth_callback"] = [callbackURL absoluteString];
    } else {
        parameters[@"oauth_callback"] = @"oob";
    }

    if (!self.accessToken && scope && ![scope isEqualToString:@""]) {
        parameters[@"scope"] = scope;
    }

    NSMutableURLRequest *request = [self requestWithMethod:accessMethod path:path parameters:parameters];

    AFHTTPRequestOperation *operation = [self HTTPRequestOperationWithRequest:request success:^(AFHTTPRequestOperation *operation, id responseObject) {
        if (success) {
            AFOAuth1Token *accessToken = [[AFOAuth1Token alloc] initWithQueryString:operation.responseString];
            success(accessToken, responseObject);
        }
    } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
        if (failure) {
            failure(error);
        }
    }];

    [self enqueueHTTPRequestOperation:operation];
}

- (void)acquireOAuthAccessTokenWithPath:(NSString *)path
                           requestToken:(AFOAuth1Token *)requestToken
                           accessMethod:(NSString *)accessMethod
                                success:(void (^)(AFOAuth1Token *accessToken, id responseObject))success
                                failure:(void (^)(NSError *error))failure
{
    if (requestToken.key) {
        self.accessToken = requestToken;
        
        NSMutableDictionary *parameters = [[self OAuthParameters] mutableCopy];
        parameters[@"oauth_token"] = requestToken.key;
        if (requestToken.verifier) {
            parameters[@"oauth_verifier"] = requestToken.verifier;
        }
        
        NSMutableURLRequest *request = [self requestWithMethod:accessMethod path:path parameters:parameters];
        
        AFHTTPRequestOperation *operation = [self HTTPRequestOperationWithRequest:request success:^(AFHTTPRequestOperation *operation, id responseObject) {
            if (success) {
                AFOAuth1Token *accessToken = [[AFOAuth1Token alloc] initWithQueryString:operation.responseString];
                success(accessToken, responseObject);
            }
        } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
            if (failure) {
                failure(error);
            }
        }];
        
        [self enqueueHTTPRequestOperation:operation];
    } else {
        NSDictionary *userInfo = [NSDictionary dictionaryWithObject:NSLocalizedStringFromTable(@"Bad OAuth response received from the server.", @"AFNetworking", nil) forKey:NSLocalizedFailureReasonErrorKey];
        NSError *error = [[NSError alloc] initWithDomain:AFNetworkingErrorDomain code:NSURLErrorBadServerResponse userInfo:userInfo];
        failure(error);
    }
}

#pragma mark -

- (void)setServiceProviderRequestHandler:(void (^)(NSURLRequest *request))block
                              completion:(void (^)())completion
{
    self.serviceProviderRequestHandler = block;
    self.serviceProviderRequestCompletion = completion;
}

#pragma mark - AFHTTPClient

- (NSMutableURLRequest *)requestWithMethod:(NSString *)method
                                      path:(NSString *)path
                                parameters:(NSDictionary *)parameters
{
    NSMutableDictionary *mutableParameters = [parameters mutableCopy];
    for (NSString *key in parameters) {
        if ([key hasPrefix:@"oauth_"]) {
            [mutableParameters removeObjectForKey:key];
        }
    }

    NSMutableURLRequest *request = [super requestWithMethod:method path:path parameters:mutableParameters];

    // Only use parameters in the request entity body (with a content-type of `application/x-www-form-urlencoded`).
    // See RFC 5849, Section 3.4.1.3.1 http://tools.ietf.org/html/rfc5849#section-3.4
    NSDictionary *authorizationParameters = parameters;
    if (!([method isEqualToString:@"GET"] || [method isEqualToString:@"HEAD"] || [method isEqualToString:@"DELETE"])) {
        authorizationParameters = ([[request valueForHTTPHeaderField:@"Content-Type"] hasPrefix:@"application/x-www-form-urlencoded"] ? parameters : nil);
    }
    
    [request setValue:[self authorizationHeaderForMethod:method path:path parameters:authorizationParameters] forHTTPHeaderField:@"Authorization"];
    [request setHTTPShouldHandleCookies:NO];
    
    return request;
}

- (NSMutableURLRequest *)multipartFormRequestWithMethod:(NSString *)method
                                                   path:(NSString *)path
                                             parameters:(NSDictionary *)parameters
                              constructingBodyWithBlock:(void (^)(id <AFMultipartFormData> formData))block
{
    NSMutableURLRequest *request = [super multipartFormRequestWithMethod:method path:path parameters:parameters constructingBodyWithBlock:block];

    // Only use parameters in the HTTP POST request body (with a content-type of `application/x-www-form-urlencoded`).
    // See RFC 5849, Section 3.4.1.3.1 http://tools.ietf.org/html/rfc5849#section-3.4
    NSDictionary *authorizationParameters = ([[request valueForHTTPHeaderField:@"Content-Type"] hasPrefix:@"application/x-www-form-urlencoded"] ? parameters : nil);
    [request setValue:[self authorizationHeaderForMethod:method path:path parameters:authorizationParameters] forHTTPHeaderField:@"Authorization"];
    [request setHTTPShouldHandleCookies:NO];
    
    return request;
}

#pragma mark - NSCoding

- (id)initWithCoder:(NSCoder *)decoder {
    self = [super initWithCoder:decoder];
    if (!self) {
        return nil;
    }

    self.key = [decoder decodeObjectForKey:NSStringFromSelector(@selector(key))];
    self.secret = [decoder decodeObjectForKey:NSStringFromSelector(@selector(secret))];
    self.signatureMethod = (AFOAuthSignatureMethod)[decoder decodeIntegerForKey:NSStringFromSelector(@selector(signatureMethod))];
    self.realm = [decoder decodeObjectForKey:NSStringFromSelector(@selector(realm))];
    self.accessToken = [decoder decodeObjectForKey:NSStringFromSelector(@selector(accessToken))];

    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [super encodeWithCoder:coder];
    
    [coder encodeObject:self.key forKey:NSStringFromSelector(@selector(key))];
    [coder encodeObject:self.secret forKey:NSStringFromSelector(@selector(secret))];
    [coder encodeInteger:self.signatureMethod forKey:NSStringFromSelector(@selector(signatureMethod))];
    [coder encodeObject:self.realm forKey:NSStringFromSelector(@selector(realm))];
    [coder encodeObject:self.accessToken forKey:NSStringFromSelector(@selector(accessToken))];
}

#pragma mark - NSCopying

- (id)copyWithZone:(NSZone *)zone {
    AFOAuth1Client *copy = [[[self class] allocWithZone:zone] initWithBaseURL:self.baseURL key:self.key secret:self.secret];
    copy.signatureMethod = self.signatureMethod;
    copy.realm = self.realm;
    copy.accessToken = self.accessToken;

    return copy;
}

@end

#pragma mark -

@interface AFOAuth1Token ()
@property (readwrite, nonatomic, copy) NSString *key;
@property (readwrite, nonatomic, copy) NSString *secret;
@property (readwrite, nonatomic, copy) NSString *session;
@property (readwrite, nonatomic, strong) NSDate *expiration;
@property (readwrite, nonatomic, assign, getter = canBeRenewed) BOOL renewable;
@end

@implementation AFOAuth1Token

- (id)initWithQueryString:(NSString *)queryString {
    if (!queryString || [queryString length] == 0) {
        return nil;
    }

    NSDictionary *attributes = AFParametersFromQueryString(queryString);
    
    if ([attributes count] == 0) {
        return nil;
    }

    NSString *key = attributes[@"oauth_token"];
    NSString *secret = attributes[@"oauth_token_secret"];
    NSString *session = attributes[@"oauth_session_handle"];
    
    NSDate *expiration = nil;
    if (attributes[@"oauth_token_duration"]) {
        expiration = [NSDate dateWithTimeIntervalSinceNow:[attributes[@"oauth_token_duration"] doubleValue]];
    }

    BOOL canBeRenewed = NO;
    if (attributes[@"oauth_token_renewable"]) {
        canBeRenewed = AFQueryStringValueIsTrue(attributes[@"oauth_token_renewable"]);
    }

    self = [self initWithKey:key secret:secret session:session expiration:expiration renewable:canBeRenewed];
    if (!self) {
        return nil;
    }

    NSMutableDictionary *mutableUserInfo = [attributes mutableCopy];
    [mutableUserInfo removeObjectsForKeys:@[@"oauth_token", @"oauth_token_secret", @"oauth_session_handle", @"oauth_token_duration", @"oauth_token_renewable"]];

    if ([mutableUserInfo count] > 0) {
        self.userInfo = [NSDictionary dictionaryWithDictionary:mutableUserInfo];
    }

    return self;
}

- (id)initWithKey:(NSString *)key
           secret:(NSString *)secret
          session:(NSString *)session
       expiration:(NSDate *)expiration
        renewable:(BOOL)canBeRenewed
{
    NSParameterAssert(key);
    NSParameterAssert(secret);

    self = [super init];
    if (!self) {
        return nil;
    }

    self.key = key;
    self.secret = secret;
    self.session = session;
    self.expiration = expiration;
    self.renewable = canBeRenewed;
    
    return self;
}

- (BOOL)isExpired{
    return [self.expiration compare:[NSDate date]] == NSOrderedAscending;
}

#pragma mark -

+ (AFOAuth1Token *)retrieveCredentialWithIdentifier:(NSString *)identifier {
    NSMutableDictionary *mutableQueryDictionary = [AFKeychainQueryDictionaryWithIdentifier(identifier) mutableCopy];
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
    NSMutableDictionary *mutableQueryDictionary = [AFKeychainQueryDictionaryWithIdentifier(identifier) mutableCopy];

    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)mutableQueryDictionary);

    if (status != errSecSuccess) {
        NSLog(@"Unable to delete credential with identifier \"%@\" (Error %li)", identifier, (long int)status);
    }

    return (status == errSecSuccess);
}

+ (BOOL)storeCredential:(AFOAuth1Token *)credential
         withIdentifier:(NSString *)identifier
{
    id securityAccessibility = nil;
#if (defined(__IPHONE_OS_VERSION_MAX_ALLOWED) && __IPHONE_OS_VERSION_MAX_ALLOWED >= 43000) || (defined(__MAC_OS_X_VERSION_MAX_ALLOWED) && __MAC_OS_X_VERSION_MAX_ALLOWED >= 1090)
    securityAccessibility = (__bridge id)kSecAttrAccessibleWhenUnlocked;
#endif
    
    return [[self class] storeCredential:credential withIdentifier:identifier withAccessibility:securityAccessibility];
}

+ (BOOL)storeCredential:(AFOAuth1Token *)credential
         withIdentifier:(NSString *)identifier
      withAccessibility:(id)securityAccessibility
{
    NSMutableDictionary *mutableQueryDictionary = [AFKeychainQueryDictionaryWithIdentifier(identifier) mutableCopy];

    if (!credential) {
        return [self deleteCredentialWithIdentifier:identifier];
    }

    NSMutableDictionary *mutableUpdateDictionary = [NSMutableDictionary dictionary];
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

#pragma mark - NSCoding

- (id)initWithCoder:(NSCoder *)decoder {
    self = [super init];
    if (!self) {
        return nil;
    }

    self.key = [decoder decodeObjectForKey:NSStringFromSelector(@selector(key))];
    self.secret = [decoder decodeObjectForKey:NSStringFromSelector(@selector(secret))];
    self.session = [decoder decodeObjectForKey:NSStringFromSelector(@selector(session))];
    self.verifier = [decoder decodeObjectForKey:NSStringFromSelector(@selector(verifier))];
    self.expiration = [decoder decodeObjectForKey:NSStringFromSelector(@selector(expiration))];
    self.renewable = [decoder decodeBoolForKey:NSStringFromSelector(@selector(canBeRenewed))];
    self.userInfo = [decoder decodeObjectForKey:NSStringFromSelector(@selector(userInfo))];

    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeObject:self.key forKey:NSStringFromSelector(@selector(key))];
    [coder encodeObject:self.secret forKey:NSStringFromSelector(@selector(secret))];
    [coder encodeObject:self.session forKey:NSStringFromSelector(@selector(session))];
    [coder encodeObject:self.verifier forKey:NSStringFromSelector(@selector(verifier))];
    [coder encodeObject:self.expiration forKey:NSStringFromSelector(@selector(expiration))];
    [coder encodeBool:self.renewable forKey:NSStringFromSelector(@selector(canBeRenewed))];
    [coder encodeObject:self.userInfo forKey:NSStringFromSelector(@selector(userInfo))];
}

#pragma mark - NSCopying

- (id)copyWithZone:(NSZone *)zone {
    AFOAuth1Token *copy = [[[self class] allocWithZone:zone] init];
    copy.key = self.key;
    copy.secret = self.secret;
    copy.session = self.session;
    copy.verifier = self.verifier;
    copy.expiration = self.expiration;
    copy.renewable = self.renewable;
    copy.userInfo = self.userInfo;

    return copy;
}

@end
