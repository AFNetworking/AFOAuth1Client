// AFOAuth1Client.m
//
// Copyright (c) 2011 Mattt Thompson (http://mattt.me/)
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

#include "hmac.h"
#include "Base64Transcoder.h"

static inline NSDictionary * AFParametersFromQueryString(NSString *queryString) {
    NSMutableDictionary *parameters = [NSMutableDictionary dictionary];
    if (queryString) {
        NSScanner *parameterScanner = [[[NSScanner alloc] initWithString:queryString] autorelease];
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
                [parameters setValue:[value stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding] forKey:[name stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding]];
            }
        }
    }
    
    return parameters;
}

static inline BOOL AFQueryStringValueIsTrue(NSString *value) {
    return value && [[value lowercaseString] hasPrefix:@"t"];
}

@interface AFOAuth1Token ()
@property (readwrite, nonatomic, copy) NSString *key;
@property (readwrite, nonatomic, copy) NSString *secret;
@property (readwrite, nonatomic, copy) NSString *session;
@property (readwrite, nonatomic, copy) NSString *verifier;
@property (readwrite, nonatomic, retain) NSDate *expiration;
@property (readwrite, nonatomic, assign, getter = canBeRenewed) BOOL renewable;
@end

@implementation AFOAuth1Token
@synthesize key = _key;
@synthesize secret = _secret;
@synthesize session = _session;
@synthesize verifier = _verifier;
@synthesize expiration = _expiration;
@synthesize renewable = _renewable;
@dynamic expired;

- (id)initWithQueryString:(NSString *)queryString {
    self = [super init];
    if (!self) {
        return nil;
    }
    
    NSDictionary *attributes = AFParametersFromQueryString(queryString);
    
    self.key = [attributes objectForKey:@"oauth_token"];
    self.secret = [attributes objectForKey:@"oauth_token_secret"];
    self.session = [attributes objectForKey:@"oauth_session_handle"];
    
    if ([attributes objectForKey:@"oauth_token_duration"]) {
        self.expiration = [NSDate dateWithTimeIntervalSinceNow:[[attributes objectForKey:@"oauth_token_duration"] doubleValue]];
    }
    
    if ([attributes objectForKey:@"oauth_token_renewable"]) {
        self.renewable = AFQueryStringValueIsTrue([attributes objectForKey:@"oauth_token_renewable"]);
    }
    
    return self;
}

@end

#pragma mark -

NSString * const kAFOAuth1Version = @"1.0";

static inline NSString * AFNonceWithPath(NSString *path) {
    return @"cmVxdWVzdF90bw";
    return AFBase64EncodedStringFromString([[NSString stringWithFormat:@"%@-%@", path, [[NSDate date] description]] substringWithRange:NSMakeRange(0, 10)]);
}

static inline NSString * NSStringFromAFOAuthSignatureMethod(AFOAuthSignatureMethod signatureMethod) {
    switch (signatureMethod) {
        case AFHMACSHA1SignatureMethod:
            return @"HMAC-SHA1";
        case AFPlaintextSignatureMethod:
            return @"PLAINTEXT";
        default:
            return nil;
    }
}

static inline NSString * AFHMACSHA1SignatureWithConsumerSecretAndRequestTokenSecret(NSURLRequest *request, NSString *consumerSecret, NSString *requestTokenSecret, NSStringEncoding stringEncoding) {
    NSString *secretString = [NSString stringWithFormat:@"%@&%@", consumerSecret, @""];
    NSData *secretStringData = [secretString dataUsingEncoding:stringEncoding];
    
    NSString *queryString = AFURLEncodedStringFromStringWithEncoding([[[[[request URL] query] componentsSeparatedByString:@"&"] sortedArrayUsingSelector:@selector(caseInsensitiveCompare:)] componentsJoinedByString:@"&"], stringEncoding);
    
    NSString *requestString = [NSString stringWithFormat:@"%@&%@&%@", [request HTTPMethod], AFURLEncodedStringFromStringWithEncoding([[[[request URL] absoluteString] componentsSeparatedByString:@"?"] objectAtIndex:0], stringEncoding), queryString];
    NSData *requestStringData = [requestString dataUsingEncoding:stringEncoding];
//    NSData *consumerSecretData = [consumerSecret dataUsingEncoding:stringEncoding];
//    NSData *requestTokenSecretData = [requestTokenSecret dataUsingEncoding:stringEncoding];
    unsigned char result[20];
    hmac_sha1((unsigned char *)[requestStringData bytes], [requestStringData length], (unsigned char *)[secretStringData bytes], [secretStringData length], result);
    
    //Base64 Encoding
    
    char base64Result[32];
    size_t theResultLength = 32;
    Base64EncodeData(result, 20, base64Result, &theResultLength);
    NSData *theData = [NSData dataWithBytes:base64Result length:theResultLength];
    
    NSLog(@"Request: %@", [[request URL] absoluteString]);
    NSLog(@"string: %@", requestString);
    NSLog(@"secret: %@", secretString);
    NSLog(@"Data: %@", [NSData dataWithBytes:result length:20]);
    NSLog(@"64: %@", [[[NSString alloc] initWithData:theData encoding:NSUTF8StringEncoding] autorelease]);
    
    
    
    return [[[NSString alloc] initWithData:theData encoding:NSUTF8StringEncoding] autorelease];
}

static inline NSString * AFPlaintextSignatureWithConsumerSecretAndRequestTokenSecret(NSString *consumerSecret, NSString *requestTokenSecret, NSStringEncoding stringEncoding) {
    // TODO
    return nil;
}

static inline NSString * AFSignatureUsingMethodWithSignatureWithConsumerSecretAndRequestTokenSecret(NSURLRequest *request, AFOAuthSignatureMethod signatureMethod, NSString *consumerSecret, NSString *requestTokenSecret, NSStringEncoding stringEncoding) {
    switch (signatureMethod) {
        case AFHMACSHA1SignatureMethod:
            return AFHMACSHA1SignatureWithConsumerSecretAndRequestTokenSecret(request, consumerSecret, requestTokenSecret, stringEncoding);
        case AFPlaintextSignatureMethod:
            return AFPlaintextSignatureWithConsumerSecretAndRequestTokenSecret(consumerSecret, requestTokenSecret, stringEncoding);
        default:
            return nil;
    }
}

@interface AFOAuth1Client ()
@property (readwrite, nonatomic, copy) NSString *key;
@property (readwrite, nonatomic, copy) NSString *secret;
@property (readwrite, nonatomic, copy) NSString *serviceProviderIdentifier;
@end

@implementation AFOAuth1Client
@synthesize key = _key;
@synthesize secret = _secret;
@synthesize serviceProviderIdentifier = _serviceProviderIdentifier;
@synthesize signatureMethod = _signatureMethod;
@synthesize realm = _realm;

- (id)initWithBaseURL:(NSURL *)url
                  key:(NSString *)clientID
               secret:(NSString *)secret
{
    self = [super initWithBaseURL:url];
    if (!self) {
        return nil;
    }
    
    self.key = clientID;
    self.secret = secret;
    
    self.serviceProviderIdentifier = [self.baseURL host];
    
    return self;
}

- (void)dealloc {
    [_key release];
    [_secret release];
    [_serviceProviderIdentifier release];
    [_realm release];
    [super dealloc];
}

- (void)authorizeUsingOAuthWithRequestTokenPath:(NSString *)requestTokenPath
                          userAuthorizationPath:(NSString *)userAuthorizationPath
                                    callbackURL:(NSURL *)callbackURL
                                accessTokenPath:(NSString *)accessTokenPath
                                        success:(void (^)(AFOAuth1Token *accessToken))success 
                                        failure:(void (^)(NSError *error))failure
{
    [self acquireOAuthRequestTokenWithPath:requestTokenPath callback:callbackURL success:^(AFOAuth1Token *requestToken) {
#if __IPHONE_OS_VERSION_MIN_REQUIRED
        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification object:nil queue:self.operationQueue usingBlock:^(NSNotification *notification) {
            NSURL *url = [[notification userInfo] valueForKey:UIApplicationLaunchOptionsURLKey];
            NSLog(@"URL: %@", url);
            
            [self acquireOAuthAccessTokenWithPath:accessTokenPath requestToken:nil success:^(AFOAuth1Token * accessToken) {
                if (success) {
                    success(accessToken);
                }
            } failure:failure];
        }];
        
        NSLog(@"Going out");
        
        NSMutableDictionary *parameters = [NSMutableDictionary dictionary];
        [parameters setValue:requestToken.key forKey:@"oauth_token"];
        
        [[UIApplication sharedApplication] openURL:[[self requestWithMethod:@"GET" path:userAuthorizationPath parameters:parameters] URL]];
#else
        [[NSNotificationCenter defaultCenter] addObserverForName:NSApplicationDidFinishLaunchingNotification object:nil queue:self.operationQueue usingBlock:^(NSNotification *notification) {
//            NSURL *url = [[notification userInfo] valueForKey:UIApplicationLaunchOptionsURLKey];
//            NSLog(@"URL: %@", url);
            
            [self acquireOAuthAccessTokenWithPath:accessTokenPath requestToken:nil success:^(AFOAuth1Token * accessToken) {
                if (success) {
                    success(accessToken);
                }
            } failure:failure];
        }];
        
        NSLog(@"Going out");
        
        NSMutableDictionary *parameters = [NSMutableDictionary dictionary];
        [parameters setValue:requestToken.key forKey:@"oauth_token"];
        
        [[NSWorkspace sharedWorkspace] openURL:[[self requestWithMethod:@"GET" path:userAuthorizationPath parameters:parameters] URL]];
#endif
    } failure:failure];
}

- (void)acquireOAuthRequestTokenWithPath:(NSString *)path
                                callback:(NSURL *)callbackURL
                                 success:(void (^)(AFOAuth1Token *requestToken))success 
                                 failure:(void (^)(NSError *error))failure
{
    [self clearAuthorizationHeader];
    
    NSMutableDictionary *parameters = [NSMutableDictionary dictionary];
    [parameters setValue:self.key forKey:@"oauth_consumer_key"];
    
    if (self.realm) {
        [parameters setValue:self.realm forKey:@"realm"];
    }
    
    [parameters setValue:AFNonceWithPath(path) forKey:@"oauth_nonce"];
    [parameters setValue:[[NSNumber numberWithInteger:floorf([[NSDate date] timeIntervalSince1970])] stringValue] forKey:@"oauth_timestamp"];
    
    [parameters setValue:NSStringFromAFOAuthSignatureMethod(self.signatureMethod) forKey:@"oauth_signature_method"];
    
    [parameters setValue:kAFOAuth1Version forKey:@"oauth_version"];
    
    NSString *callbackString = AFURLEncodedStringFromStringWithEncoding([callbackURL absoluteString], self.stringEncoding);
    [parameters setValue:[callbackString stringByReplacingOccurrencesOfString:@"%" withString:@"%25"] forKey:@"oauth_callback"];

    
    NSMutableURLRequest *mutableRequest = [self requestWithMethod:@"GET" path:path parameters:parameters];
    [mutableRequest setHTTPMethod:@"POST"];
    
    [parameters setValue:AFSignatureUsingMethodWithSignatureWithConsumerSecretAndRequestTokenSecret(mutableRequest, self.signatureMethod, self.secret, nil, self.stringEncoding) forKey:@"oauth_signature"];
    
    [parameters setValue:[callbackURL absoluteString] forKey:@"oauth_callback"];

    
    NSArray *sortedComponents = [[AFQueryStringFromParametersWithEncoding(parameters, self.stringEncoding) componentsSeparatedByString:@"&"] sortedArrayUsingSelector:@selector(caseInsensitiveCompare:)];
    NSMutableArray *mutableComponents = [NSMutableArray array];
    for (NSString *component in sortedComponents) {
        NSArray *subcomponents = [component componentsSeparatedByString:@"="];
        [mutableComponents addObject:[NSString stringWithFormat:@"%@=\"%@\"", [subcomponents objectAtIndex:0], [subcomponents objectAtIndex:1]]];
    }
    
    NSString *oauthString = [NSString stringWithFormat:@"OAuth %@", [mutableComponents componentsJoinedByString:@", "]];
    
    NSLog(@"OAuth: %@", oauthString);
    
    [self setDefaultHeader:@"Authorization" value:oauthString];
    
    [self postPath:path parameters:nil success:^(AFHTTPRequestOperation *operation, id responseObject) {
        NSLog(@"Success: %@", operation.responseString);
        
        if (success) {
            AFOAuth1Token *requestToken = [[[AFOAuth1Token alloc] initWithQueryString:operation.responseString] autorelease];
            success(requestToken);
        }
    } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
        NSLog(@"Failure: %@", operation.responseString);
        if (failure) {
            failure(error);
        }
    }];
}

- (void)acquireOAuthAccessTokenWithPath:(NSString *)path
                           requestToken:(AFOAuth1Token *)requestToken
                                success:(void (^)(AFOAuth1Token *accessToken))success 
                                failure:(void (^)(NSError *error))failure
{
    [self clearAuthorizationHeader];
        
    NSMutableDictionary *parameters = [NSMutableDictionary dictionary];
    [parameters setValue:self.key forKey:@"oauth_consumer_key"];
    [parameters setValue:requestToken.key forKey:@"oauth_token"];
    [parameters setValue:requestToken.verifier forKey:@"oauth_verifier"];

    if (self.realm) {
        [parameters setValue:self.realm forKey:@"realm"];
    }
    
    [parameters setValue:AFNonceWithPath(path) forKey:@"oauth_nonce"];
    [parameters setValue:[[NSNumber numberWithInteger:floorf([[NSDate date] timeIntervalSince1970])] stringValue] forKey:@"oauth_timestamp"];
    
    [parameters setValue:NSStringFromAFOAuthSignatureMethod(self.signatureMethod) forKey:@"oauth_signature_method"];
    [parameters setValue:AFSignatureUsingMethodWithSignatureWithConsumerSecretAndRequestTokenSecret([self requestWithMethod:@"POST" path:path parameters:parameters], self.signatureMethod, self.secret, requestToken.secret, self.stringEncoding) forKey:@"oauth_signature"];
    
    [parameters setValue:kAFOAuth1Version forKey:@"oauth_version"];
    
    [self setDefaultHeader:@"Authorization" value:AFQueryStringFromParametersWithEncoding(parameters, self.stringEncoding)];
    
    [self postPath:path parameters:nil success:^(AFHTTPRequestOperation *operation, id responseObject) {
        NSLog(@"Success: %@", operation.responseString);
        
        if (success) {
            AFOAuth1Token *accessToken = [[[AFOAuth1Token alloc] initWithQueryString:operation.responseString] autorelease];
            success(accessToken);
        }
    } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
        NSLog(@"Failure: %@", error);
        
        if (failure) {
            failure(error);
        }
    }];
}

- (NSMutableURLRequest *)requestWithMethod:(NSString *)method path:(NSString *)path parameters:(NSDictionary *)parameters {
    NSMutableURLRequest *request = [super requestWithMethod:method path:path parameters:parameters];
    [request setHTTPShouldHandleCookies:NO];
    return  request;
}

@end
