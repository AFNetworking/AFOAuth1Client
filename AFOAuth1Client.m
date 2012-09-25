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
//
// Version modded by Cristiano Severini (crino)
//

#import "AFOAuth1Client.h"

#import "AFHTTPRequestOperation.h"

#import <CommonCrypto/CommonHMAC.h>

#if !__has_feature(objc_arc)
#error "AFOAuth1Client needs to be compiled with ARC enabled."
#endif

// copied from AFHttpClient
static NSString * AFPercentEscapedQueryStringPairMemberFromStringWithEncoding(NSString *string, NSStringEncoding encoding) {
    // Escape characters that are legal in URIs, but have unintentional semantic significance when used in a query string parameter
    static NSString * const kAFLegalCharactersToBeEscaped = @":/.?&=;+!@$()~";
    
	return (__bridge_transfer  NSString *)CFURLCreateStringByAddingPercentEscapes(kCFAllocatorDefault, (__bridge CFStringRef)string, NULL, (__bridge CFStringRef)kAFLegalCharactersToBeEscaped, CFStringConvertNSStringEncodingToEncoding(encoding));
}

NSString * const kAFOAuth1Version = @"1.0";

#pragma mark static

static inline NSDictionary * AFParametersFromQueryString(NSString *queryString) {
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
                [parameters setValue:[value stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding] forKey:[name stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding]];
            }
        }
    }
    
    return parameters;
}

static inline BOOL AFQueryStringValueIsTrue(NSString *value) {
    return (value && [[value lowercaseString] hasPrefix:@"t"]);
}

static inline NSString * AFNonce() {
    CFUUIDRef uuid = CFUUIDCreate(NULL);
    NSString* string = (__bridge_transfer NSString*) CFUUIDCreateString(NULL, uuid);
    CFRelease(uuid);
    return string;
}

static inline NSString * NSStringFromAFOAuthSignatureMethod(AFOAuthSignatureMethod signatureMethod) {
    switch (signatureMethod) {
        case AFSignatureMethodHMACSHA1:
            return @"HMAC-SHA1";
        case AFSignatureMethodPlaintext:
            return @"PLAINTEXT";
        default:
            return nil;
    }
}

static inline NSString* AFSortedQueryStringWithDictionary(NSDictionary* parameters) {
    NSArray* sortedKeys = [[parameters allKeys] sortedArrayUsingSelector:@selector(caseInsensitiveCompare:)];
    NSMutableArray* sortedParams = [NSMutableArray arrayWithCapacity:parameters.count];
    for (NSString *key in sortedKeys) {
        [sortedParams addObject:[NSString stringWithFormat:@"%@=%@", key, [parameters valueForKey:key]]];
    }
    return [sortedParams componentsJoinedByString:@"&"];
}

static inline NSDictionary * AFParametersFromBodyStringWithBoundary(NSString *boundaryString, NSString *bodyString) {
    NSMutableDictionary* params = [NSMutableDictionary dictionary];
    if (bodyString && boundaryString) {
        NSRegularExpression* regexp = [NSRegularExpression regularExpressionWithPattern:@"name=\"(.*)\"\\r\\n\\r\\n(.*)"
                                                                                options:NSRegularExpressionCaseInsensitive
                                                                                  error:NULL];
        [regexp enumerateMatchesInString:bodyString
                                 options:NSMatchingReportCompletion
                                   range:NSMakeRange(0, bodyString.length)
                              usingBlock:^(NSTextCheckingResult *result, NSMatchingFlags flags, BOOL *stop) {
                                  if (result.numberOfRanges == 3) {
                                      NSString* name = [bodyString substringWithRange:[result rangeAtIndex:1]];
                                      NSString* value = [bodyString substringWithRange:[result rangeAtIndex:2]];
                                      [params setValue:value forKey:name];
                                  }
                              }];
    }
    return params;
}

static const char _b64EncTable[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static inline NSString * AFEncodeBase64WithData(NSData *data) {
    const unsigned char * rawData = [data bytes];
    char * out;
    char * result;
    
    int lenght = (int)[data length];
    if (lenght == 0) return nil;
    
    result = (char *)calloc((((lenght + 2) / 3) * 4) + 1, sizeof(char));
    out = result;
    
    while (lenght > 2) {
        *out++ = _b64EncTable[rawData[0] >> 2];
        *out++ = _b64EncTable[((rawData[0] & 0x03) << 4) + (rawData[1] >> 4)];
        *out++ = _b64EncTable[((rawData[1] & 0x0f) << 2) + (rawData[2] >> 6)];
        *out++ = _b64EncTable[rawData[2] & 0x3f];
        
        rawData += 3;
        lenght -= 3;
    }
    
    if (lenght != 0) {
        *out++ = _b64EncTable[rawData[0] >> 2];
        if (lenght > 1) {
            *out++ = _b64EncTable[((rawData[0] & 0x03) << 4) + (rawData[1] >> 4)];
            *out++ = _b64EncTable[(rawData[1] & 0x0f) << 2];
            *out++ = '=';
        } else {
            *out++ = _b64EncTable[(rawData[0] & 0x03) << 4];
            *out++ = '=';
            *out++ = '=';
        }
    }
    
    *out = '\0';
    
    return [NSString stringWithCString:result encoding:NSASCIIStringEncoding];
}


static inline NSString * AFHMACSHA1SignatureWithConsumerSecretAndRequestTokenSecret(NSURLRequest* request, NSDictionary* params, NSString *consumerSecret, NSString *requestTokenSecret, NSStringEncoding stringEncoding) {

    NSString *secretString = [NSString stringWithFormat:@"%@&%@", consumerSecret, (requestTokenSecret != nil ? requestTokenSecret : @"")];
    NSData *secretStringData = [secretString dataUsingEncoding:stringEncoding];
    
    NSArray *sortedComponents = [[AFQueryStringFromParametersWithEncoding(params, stringEncoding) componentsSeparatedByString:@"&"] sortedArrayUsingSelector:@selector(caseInsensitiveCompare:)];
    NSString* queryString = AFPercentEscapedQueryStringPairMemberFromStringWithEncoding([sortedComponents componentsJoinedByString:@"&"], stringEncoding);
    
    NSString *requestString = [NSString stringWithFormat:@"%@&%@&%@", [request HTTPMethod], AFPercentEscapedQueryStringPairMemberFromStringWithEncoding([[[[request URL] absoluteString] componentsSeparatedByString:@"?"] objectAtIndex:0], stringEncoding), queryString];
    NSData *requestStringData = [requestString dataUsingEncoding:stringEncoding];
    
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CCHmacContext ctx;
    CCHmacInit(&ctx, kCCHmacAlgSHA1, [secretStringData bytes], [secretStringData length]);
    CCHmacUpdate(&ctx, [requestStringData bytes], [requestStringData length]);
    CCHmacFinal(&ctx, digest);
    
    NSData* data = [NSData dataWithBytes:digest length:CC_SHA1_DIGEST_LENGTH];
    NSString* signature = AFEncodeBase64WithData(data);
    
    NSLog(@"Request: %@", [[request URL] absoluteString]);
    NSLog(@"string: %@", requestString);
    NSLog(@"secret: %@", secretString);
    NSLog(@"Data: %@", data);
    NSLog(@"64: %@", signature);
    
    return signature;
}

static inline NSString * AFPlaintextSignatureWithConsumerSecretAndRequestTokenSecret(NSString *consumerSecret, NSString *requestTokenSecret, NSStringEncoding stringEncoding) {
    NSString *secretString = [NSString stringWithFormat:@"%@&%@", consumerSecret, (requestTokenSecret != nil ? requestTokenSecret : @"")];
    return secretString;
}

static inline NSString * AFSignatureUsingMethodWithSignatureWithConsumerSecretAndRequestTokenSecret(NSURLRequest *request, NSDictionary* params, AFOAuthSignatureMethod signatureMethod, NSString *consumerSecret, NSString *requestTokenSecret, NSStringEncoding stringEncoding) {
    switch (signatureMethod) {
        case AFSignatureMethodHMACSHA1:
            return AFHMACSHA1SignatureWithConsumerSecretAndRequestTokenSecret(request, params, consumerSecret, requestTokenSecret, stringEncoding);
        case AFSignatureMethodPlaintext:
            return AFPlaintextSignatureWithConsumerSecretAndRequestTokenSecret(consumerSecret, requestTokenSecret, stringEncoding);
        default:
            return nil;
    }
}

#pragma mark - AFOAuth1Token

@interface AFOAuth1Token ()

@property (nonatomic, copy, readwrite) NSDictionary* extras;

@property (nonatomic, copy, readwrite) NSString *token;
@property (nonatomic, copy, readwrite) NSString *tokenSecret;
@property (nonatomic, copy, readwrite) NSString *session;
@property (nonatomic, copy, readwrite) NSString *verifier;
@property (nonatomic, copy, readwrite) NSDate *expiration;
@property (nonatomic, assign, readwrite, getter = canBeRenewed) BOOL renewable;
@end

@implementation AFOAuth1Token

@dynamic expired;

-(id)initWithToken:(NSString*)token tokenSecret:(NSString*)tokenSecret {
    return [self initWithToken:token tokenSecret:tokenSecret session:nil expiration:nil reneable:NO];
}

-(id)initWithToken:(NSString*)token tokenSecret:(NSString*)tokenSecret session:(NSString*)session expiration:(NSDate*)expiration reneable:(BOOL)renewable {
    self = [super init];
    if (self) {
        self.token = token;
        self.tokenSecret = tokenSecret;
        self.session = session;
        self.expiration = expiration;
        self.renewable = renewable;
    }
    return self;
}

- (id)initWithQueryString:(NSString *)queryString {
    self = [super init];
    if (self) {
        NSMutableDictionary *attributes = [AFParametersFromQueryString(queryString) mutableCopy];
        
        self.token = [attributes objectForKey:@"oauth_token"];
        [attributes removeObjectForKey:@"oauth_token"];
        self.tokenSecret = [attributes objectForKey:@"oauth_token_secret"];
        [attributes removeObjectForKey:@"oauth_token_secret"];
        self.session = [attributes objectForKey:@"oauth_session_handle"];
        [attributes removeObjectForKey:@"oauth_session_handle"];
        if ([attributes objectForKey:@"oauth_token_duration"]) {
            self.expiration = [NSDate dateWithTimeIntervalSinceNow:[[attributes objectForKey:@"oauth_token_duration"] doubleValue]];
            [attributes removeObjectForKey:@"oauth_token_duration"];
        }
        
        if ([attributes objectForKey:@"oauth_token_renewable"]) {
            self.renewable = AFQueryStringValueIsTrue([attributes objectForKey:@"oauth_token_renewable"]);
            [attributes removeObjectForKey:@"oauth_token_renewable"];
        }
        
        self.extras = attributes;
    }
    return self;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"<%@ token:\"%@\" tokenSecret:\"%@ session:\"%@\" expiration:\"%@\" renewable:\"%d\" extras:\"%@\">", [self class], self.token, self.tokenSecret, self.session, self.expiration, self.renewable, self.extras];
}

- (BOOL)isExpired {
    return ([self.expiration compare:[NSDate date]] == NSOrderedAscending);
}

@end


#pragma mark - NSURL+AFQueryExtraction

@interface NSURL (AFQueryExtraction)
- (NSString *)AF_getParamNamed:(NSString *)paramName;
@end

@implementation NSURL (AFQueryExtraction)

- (NSString *)AF_getParamNamed:(NSString *)paramName {
    NSString* query = [self query];
    
    NSScanner *scanner = [NSScanner scannerWithString:query];
    NSString *searchString = [[NSString alloc] initWithFormat:@"%@=",paramName];
    [scanner scanUpToString:searchString intoString:nil];
    NSUInteger startPos = [scanner scanLocation] + [searchString length];
    [scanner scanUpToString:@"&" intoString:nil];
    NSUInteger endPos = [scanner scanLocation];
    return [query substringWithRange:NSMakeRange(startPos, endPos - startPos)];
}

@end

#pragma mark - AFOAuth1Client

typedef NSString*(^AFNonceBlock)();
typedef void(^success_block)(AFOAuth1Token* token);
typedef void(^failure_block)(NSError* error);

@interface AFOAuth1Client()

@property (nonatomic, copy, readwrite) NSURL* callbackURL;

@property (nonatomic, copy, readwrite) NSString* clientKey;
@property (nonatomic, copy, readwrite) NSString* clientSecret;

@property (nonatomic, copy) NSString* accessTokenPath;
@property (nonatomic, copy) NSString* accessMethod;

@property (nonatomic, copy, readwrite) AFNonceBlock nonce;

@property (nonatomic, copy, readwrite) success_block success_block;
@property (nonatomic, copy, readwrite) failure_block failure_block;

@end


@implementation AFOAuth1Client

- (id)initWithBaseURL:(NSURL *)url clientKey:(NSString *)clientKey clientSecret:(NSString *)clientSecret {
    self = [super initWithBaseURL:url];
    if (self) {
        self.clientKey = clientKey;
        self.clientSecret = clientSecret;
        
        self.accessToken = nil;
        self.oauthMethod = AFOAuthMethodHeader;
        
        self.nonce = nil;
    }
    return self;
}

#pragma mark Private methods

-(NSDictionary*)oauthParameters {
    NSMutableDictionary *oauthParams = [NSMutableDictionary dictionaryWithCapacity:6];
    [oauthParams setValue:self.clientKey forKey:@"oauth_consumer_key"];
    if (self.accessToken.token) {
        [oauthParams setValue:self.accessToken.token forKey:@"oauth_token"];
    }
    [oauthParams setValue:NSStringFromAFOAuthSignatureMethod(self.signatureMethod) forKey:@"oauth_signature_method"];
    [oauthParams setValue:[[NSNumber numberWithInteger:floorf([[NSDate date] timeIntervalSince1970])] stringValue] forKey:@"oauth_timestamp"];
    NSString* nonce = nil;
    if (self.nonce) {
        nonce = self.nonce();
    } else {
        nonce = AFNonce();
    }
    [oauthParams setValue:nonce forKey:@"oauth_nonce"];
    [oauthParams setValue:kAFOAuth1Version forKey:@"oauth_version"];
    return oauthParams;
}

-(void)oauthSignRequest:(NSMutableURLRequest*)request secret:(NSString*)secret parameters:(NSDictionary*)parameters {
    
    NSMutableDictionary *allParams = [NSMutableDictionary dictionaryWithDictionary:parameters];
    
    NSString* signature = AFSignatureUsingMethodWithSignatureWithConsumerSecretAndRequestTokenSecret(request, parameters, self.signatureMethod, self.clientSecret, secret, self.stringEncoding);
    [allParams setValue:signature forKey:@"oauth_signature"];
    
    // get all oauth params
    NSMutableDictionary* oauthParams = [NSMutableDictionary dictionaryWithCapacity:7];
    [allParams enumerateKeysAndObjectsUsingBlock:^(NSString* key, id obj, BOOL *stop) {
        if ([key hasPrefix:@"oauth_"]) {
            [oauthParams setObject:[allParams objectForKey:key] forKey:key];
        }
    }];
    
    
    NSArray *sortedComponents = [[AFQueryStringFromParametersWithEncoding(oauthParams, self.stringEncoding) componentsSeparatedByString:@"&"] sortedArrayUsingSelector:@selector(caseInsensitiveCompare:)];
    switch (self.oauthMethod) {
        case AFOAuthMethodGet:
        {
            NSURL* url = [NSURL URLWithString:[[request.URL absoluteString] stringByAppendingFormat:[[request.URL absoluteString] rangeOfString:@"?"].location == NSNotFound ? @"?%@" : @"&%@", [sortedComponents componentsJoinedByString:@"&"]]];
            request.URL = url;
        }
            break;
        case AFOAuthMethodPost:
        {
            if ([[request valueForHTTPHeaderField:@"Content-Type"] rangeOfString:@"application/x-www-form-urlencoded"].location != NSNotFound) {
                NSString* bodyRequest = [[NSString alloc] initWithData:request.HTTPBody encoding:NSUTF8StringEncoding];
                NSMutableString* newBody = [NSMutableString stringWithString:bodyRequest];
                if (newBody.length > 0) {
                    [newBody appendFormat:@"&%@", [sortedComponents componentsJoinedByString:@"&"]];
                } else {
                    [newBody appendString:[sortedComponents componentsJoinedByString:@"&"]];
                }
                [request setHTTPBody:[newBody dataUsingEncoding:self.stringEncoding]];
                break;
            }
            // else go on and add oauth in header
        }
        case AFOAuthMethodHeader:
        default:
        {
            NSMutableArray *mutableComponents = [NSMutableArray array];
            for (NSString *component in sortedComponents) {
                NSArray *subcomponents = [component componentsSeparatedByString:@"="];
                [mutableComponents addObject:[NSString stringWithFormat:@"%@=\"%@\"", [subcomponents objectAtIndex:0], [subcomponents objectAtIndex:1]]];
            }
            NSString *oauthHeaderString = nil;
            if (self.realm) {
                oauthHeaderString = [NSString stringWithFormat:@"OAuth realm=\"%@\", %@", self.realm, [mutableComponents componentsJoinedByString:@", "]];
            } else {
                oauthHeaderString = [NSString stringWithFormat:@"OAuth %@", [mutableComponents componentsJoinedByString:@", "]];
            }
            
            [request setValue:oauthHeaderString forHTTPHeaderField:@"Authorization"];
        }
            break;
    }
}

-(NSDictionary*)parametersFromRequest:(NSURLRequest*)request {
    NSMutableDictionary* parameters = [NSMutableDictionary dictionary];
    
    [parameters addEntriesFromDictionary:AFParametersFromQueryString([request.URL query])];
    
    NSString* contentType = [request.allHTTPHeaderFields valueForKey:@"Content-Type"];
    
    if ([request.HTTPMethod isEqualToString:@"POST"] &&
        [contentType rangeOfString:@"application/x-www-form-urlencoded"].location != NSNotFound) {
        NSString* bodyParameters = [[NSString alloc] initWithData:request.HTTPBody encoding:self.stringEncoding];
        [parameters addEntriesFromDictionary:AFParametersFromQueryString(bodyParameters)];
    }
    else if ([request.HTTPMethod isEqualToString:@"POST"] &&
             [contentType rangeOfString:@"multipart/form-data; boundary="].location != NSNotFound) {
        NSRange range = [contentType rangeOfString:@"multipart/form-data; boundary="];
        NSString* boundary = [contentType substringFromIndex:(range.location + range.length)];
        NSString* body = [[NSString alloc] initWithData:request.HTTPBody encoding:NSUTF8StringEncoding];
        [parameters addEntriesFromDictionary:AFParametersFromBodyStringWithBoundary(boundary, body)];
    }
    return parameters;
}

#pragma mark Public methods

-(void)setNonceBlock:(NSString*(^)())block {
    self.nonce = block;
}


-(BOOL)handleURL:(NSURL*)url {
    // If the URL's structure doesn't match the structure used for Instagram authorization, abort.
    if (![[url absoluteString] hasPrefix:[self.callbackURL absoluteString]]) {
        return NO;
    }
    
    NSLog(@"URL: %@", url);

    self.accessToken.verifier = [url AF_getParamNamed:@"oauth_verifier"];
    
    NSLog(@"verifier %@", self.accessToken.verifier);

    [self acquireOAuthAccessTokenWithPath:self.accessTokenPath
                             requestToken:self.accessToken
                             accessMethod:self.accessMethod
                                  success:^(AFOAuth1Token * accessToken) {
                                      if (self.success_block) {
                                          self.success_block(accessToken);
                                      }
                                  }
                                  failure:^(NSError *error) {
                                      if (self.failure_block) {
                                          self.failure_block(error);
                                      }
                                  }];
    return YES;
}


- (void)authorizeUsingOAuthWithRequestTokenPath:(NSString *)requestTokenPath
                          userAuthorizationPath:(NSString *)userAuthorizationPath
                                    callbackURL:(NSURL *)callbackURL
                                accessTokenPath:(NSString *)accessTokenPath
                                   accessMethod:(NSString *)accessMethod
                                        success:(void (^)(AFOAuth1Token *accessToken))success
                                        failure:(void (^)(NSError *error))failure {
    self.accessTokenPath = accessTokenPath;
    self.accessMethod = accessMethod;
    
    [self acquireOAuthRequestTokenWithPath:requestTokenPath
                                  callback:callbackURL
                              accessMethod:(NSString *)accessMethod
                                   success:^(AFOAuth1Token *requestToken) {

                                       NSURL* url = [NSURL URLWithString:[NSString stringWithFormat:@"%@%@?oauth_token=%@", self.baseURL, userAuthorizationPath, requestToken.token] ];
                                       NSLog(@"Going out... %@", url);
#if __IPHONE_OS_VERSION_MIN_REQUIRED
                                       [[UIApplication sharedApplication] openURL:url];
#else
                                       [[NSWorkspace sharedWorkspace] openURL:URL];
#endif
                                   }
                                   failure:^(NSError *error) {
                                       if (failure) {
                                           failure(error);
                                       }
                                   }];
}

- (void)acquireOAuthRequestTokenWithPath:(NSString *)requestTokenPath
                                callback:(NSURL *)callbackURL
                            accessMethod:(NSString *)accessMethod
                                 success:(void (^)(AFOAuth1Token *requestToken))success
                                 failure:(void (^)(NSError *error))failure {

    [self clearAuthorizationHeader];

    self.callbackURL = callbackURL;
    
    NSDictionary* parameters = [NSDictionary dictionaryWithObject:self.callbackURL forKey:@"oauth_callback"];
    [self enqueueOAuthOperationWithMethod:accessMethod
                                     path:requestTokenPath
                               parameters:parameters
                                  success:^(AFHTTPRequestOperation *operation, id responseObject) {
                                      NSLog(@"Success: %@", operation.responseString);                                      
                                      if (success) {
                                          AFOAuth1Token *requestToken = [[AFOAuth1Token alloc] initWithQueryString:operation.responseString];
                                          success(requestToken);
                                      }
                                  }
                                  failure:^(AFHTTPRequestOperation *operation, NSError *error) {
                                      NSLog(@"Failure: %@", operation.responseString);
                                      if (failure) {
                                          failure(error);
                                      }                                      
                                  }];
}


- (void)acquireOAuthAccessTokenWithPath:(NSString *)accessTokenPath
                           requestToken:(AFOAuth1Token *)requestToken
                           accessMethod:(NSString *)accessMethod
                                success:(void (^)(AFOAuth1Token *accessToken))success
                                failure:(void (^)(NSError *error))failure {
    
    [self clearAuthorizationHeader];

    self.accessToken = requestToken;
    NSDictionary* parameters = [NSDictionary dictionaryWithObjectsAndKeys:
                                self.callbackURL, @"oauth_callback",
                                requestToken.verifier, @"oauth_verifier", nil];
    
    [self enqueueOAuthOperationWithMethod:accessMethod
                                     path:accessTokenPath
                               parameters:parameters
                                  success:^(AFHTTPRequestOperation *operation, id responseObject) {
                                      NSLog(@"Success: %@", operation.responseString);                                      
                                      if (success) {
                                          AFOAuth1Token* accessToken = [[AFOAuth1Token alloc] initWithQueryString:operation.responseString];
                                          self.accessToken = accessToken;
                                          success(accessToken);
                                      }                                      
                                  }
                                  failure:^(AFHTTPRequestOperation *operation, NSError *error) {
                                      NSLog(@"Failure: %@", operation.responseString);
                                      if (failure) {
                                          failure(error);
                                      }                                      
                                  }];
}

-(void)enqueueOAuthOperationWithMethod:(NSString*)method
                                  path:(NSString*)path
                            parameters:(NSDictionary*)parameters
                               success:(void(^)(AFHTTPRequestOperation *operation, id responseObject))success
                               failure:(void(^)(AFHTTPRequestOperation *operation, NSError *error))failure {
    // create the request
    NSMutableURLRequest* request = [self requestWithMethod:method path:path parameters:parameters];
    // get the default oauth parameters
    NSMutableDictionary* allParams = [NSMutableDictionary dictionaryWithDictionary:[self oauthParameters]];
    // append the user's parameters
    [allParams addEntriesFromDictionary:[self parametersFromRequest:request]];
    // sign the request
    [self oauthSignRequest:request secret:self.accessToken.tokenSecret parameters:allParams];
    // create the operation
    AFHTTPRequestOperation* requestOperation = [self HTTPRequestOperationWithRequest:request
                                                                             success:success
                                                                             failure:failure];
//    NSLog(@"enqueueOAuthOperation: %@", requestOperation);
    [self enqueueHTTPRequestOperation:requestOperation];
}

-(NSMutableURLRequest*)multipartFormOAuthRequestWithMethod:(NSString *)method
                                                      path:(NSString *)path
                                                parameters:(NSDictionary *)parameters
                                 constructingBodyWithBlock:(void (^)(id<AFMultipartFormData>))block {
    NSMutableURLRequest* request = [super multipartFormRequestWithMethod:method
                                                                    path:path
                                                              parameters:parameters
                                               constructingBodyWithBlock:block];
    NSMutableDictionary* allParams = [NSMutableDictionary dictionaryWithDictionary:[self oauthParameters]];
    [allParams addEntriesFromDictionary:[self parametersFromRequest:request]];
    [self oauthSignRequest:request secret:self.accessToken.tokenSecret parameters:allParams];
    
    return request;
}

- (void)getOAuthPath:(NSString *)path
     parameters:(NSDictionary *)parameters
        success:(void (^)(AFHTTPRequestOperation *operation, id responseObject))success
        failure:(void (^)(AFHTTPRequestOperation *operation, NSError *error))failure
{
    [self enqueueOAuthOperationWithMethod:@"GET"
                                     path:path
                               parameters:parameters
                                  success:success
                                  failure:failure];
}

- (void)postOAuthPath:(NSString *)path
      parameters:(NSDictionary *)parameters
         success:(void (^)(AFHTTPRequestOperation *operation, id responseObject))success
         failure:(void (^)(AFHTTPRequestOperation *operation, NSError *error))failure
{
    [self enqueueOAuthOperationWithMethod:@"POST"
                                     path:path
                               parameters:parameters
                                  success:success
                                  failure:failure];
}

@end
