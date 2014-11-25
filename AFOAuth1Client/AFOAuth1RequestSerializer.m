//
//  AFOAuth1RequestSerializer.m
//  
//
//  Created by Stan Chang Khin Boon on 12/11/14.
//
//

#import "AFOAuth1RequestSerializer.h"

#import <CommonCrypto/CommonHMAC.h>

#import "AFOAuth1Token.h"
#import "AFOAuth1Utils.h"

static NSString * const kAFOAuth1Version = @"1.0";

static inline NSString * AFOAuth1Nounce() {
    CFUUIDRef uuid = CFUUIDCreate(NULL);
    CFStringRef string = CFUUIDCreateString(NULL, uuid);
    CFRelease(uuid);
    return (NSString *)CFBridgingRelease(string);
}

static inline NSString * NSStringFromAFOAuth1SignatureMethod(AFOAuth1SignatureMethod signatureMethod) {
    switch (signatureMethod) {
        case AFOAuth1PlainTextSignatureMethod: {
            return @"PLAINTEXT";
        } break;
        case AFOAuth1HMACSHA1SignatureMethod: {
            return @"HMAC-SHA1";
        } break;
        default: {
            [NSException raise:NSInternalInconsistencyException format:@"Unknown OAuth 1.0a Signature Method: %lu", (unsigned long)signatureMethod];
            return nil;
        } break;
    }
}

static inline NSString * AFOAuth1PlainTextSignature(NSURLRequest *request, NSString *consumerSecret, NSString *tokenSecret, NSStringEncoding stringEncoding) {
    NSString *secret = tokenSecret ? tokenSecret : @"";
    NSString *signature = [NSString stringWithFormat:@"%@&%@", consumerSecret, secret];
    return signature;
}

static inline NSString * AFOAuth1HMACSHA1Signature(NSURLRequest *request, NSString *consumerSecret, NSString *tokenSecret, NSStringEncoding stringEncoding) {
    NSString *secret = tokenSecret ? tokenSecret : @"";
    NSString *secretString = [NSString stringWithFormat:@"%@&%@", [AFOAuth1Utils percentEscapedQueryStringPairMemberFromString:consumerSecret withEncoding:stringEncoding], [AFOAuth1Utils percentEscapedQueryStringPairMemberFromString:secret withEncoding:stringEncoding]];
    NSData *secretStringData = [secretString dataUsingEncoding:stringEncoding];
    
    NSString *queryString = [AFOAuth1Utils percentEscapedQueryStringPairMemberFromString:[AFOAuth1Utils sortedQueryString:request.URL.query] withEncoding:stringEncoding];
    NSString *urlWithoutQueryString = [AFOAuth1Utils percentEscapedQueryStringPairMemberFromString:[request.URL.absoluteString componentsSeparatedByString:@"?"][0] withEncoding:stringEncoding];
    NSString *requestString = [NSString stringWithFormat:@"%@&%@&%@", request.HTTPMethod, urlWithoutQueryString, queryString];
    NSData *requestStringData = [requestString dataUsingEncoding:stringEncoding];
    
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CCHmacContext cx;
    CCHmacInit(&cx, kCCHmacAlgSHA1, secretStringData.bytes, secretStringData.length);
    CCHmacUpdate(&cx, requestStringData.bytes, requestStringData.length);
    CCHmacFinal(&cx, digest);
    
    return [[NSData dataWithBytes:digest length:CC_SHA1_DIGEST_LENGTH] base64EncodedStringWithOptions:0];
}

@interface AFOAuth1RequestSerializer ()

@property (nonatomic, copy) NSString *key;
@property (nonatomic, copy) NSString *secret;

@end

@implementation AFOAuth1RequestSerializer

// FIXME: (me@lxcid.com) Implements NSCoding & NSCopying.

+ (instancetype)serializerWithKey:(NSString *)key secret:(NSString *)secret {
    NSParameterAssert(key);
    NSParameterAssert(secret);
    
    AFOAuth1RequestSerializer *serializer = [self serializer];
    serializer.key = key;
    serializer.secret = secret;
    serializer.signatureMethod = AFOAuth1HMACSHA1SignatureMethod;
    
    return serializer;
}

- (NSDictionary *)oauthParameters {
    NSMutableDictionary *parameters = [[NSMutableDictionary alloc] init];
    parameters[@"oauth_version"] = kAFOAuth1Version;
    parameters[@"oauth_signature_method"] = NSStringFromAFOAuth1SignatureMethod(self.signatureMethod);
    parameters[@"oauth_consumer_key"] = self.key;
    parameters[@"oauth_timestamp"] = [NSString stringWithFormat:@"%.0f", [[NSDate date] timeIntervalSince1970]];
    parameters[@"oauth_nonce"] = AFOAuth1Nounce();
    if (self.realm) {
        parameters[@"realm"] = self.realm;
    }
    return [parameters copy];
}

- (NSString *)oauthSignatureForMethod:(NSString *)method URLString:(NSString *)URLString parameters:(NSDictionary *)parameters token:(AFOAuth1Token *)token error:(NSError * __autoreleasing *)error {
    NSMutableURLRequest *request = [super requestWithMethod:@"GET" URLString:URLString parameters:parameters error:error];
    if (!request) {
        return nil;
    }
    [request setHTTPMethod:method];
    
    NSString *tokenSecret = token ? token.secret : nil;
    
    switch (self.signatureMethod) {
        case AFOAuth1PlainTextSignatureMethod: {
            return AFOAuth1PlainTextSignature(request, self.secret, tokenSecret, self.stringEncoding);
        } break;
        case AFOAuth1HMACSHA1SignatureMethod: {
            return AFOAuth1HMACSHA1Signature(request, self.secret, tokenSecret, self.stringEncoding);
        } break;
        default: {
            [NSException raise:NSInternalInconsistencyException format:@"Unknown OAuth 1.0a Signature Method: %lu", (unsigned long)self.signatureMethod];
            return nil;
        } break;
    }
}

- (NSString *)authorizationHeaderForMethod:(NSString *)method URLString:(NSString *)URLString parameters:(NSDictionary *)parameters error:(NSError * __autoreleasing *)error {
    NSMutableDictionary *mutableParameters = parameters ? [parameters mutableCopy] : [NSMutableDictionary dictionary];
    NSMutableDictionary *mutableAuthorizationParameters = [NSMutableDictionary dictionary];
    
    if (self.key && self.secret) {
        [mutableAuthorizationParameters addEntriesFromDictionary:self.oauthParameters];
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
    NSString *oauthSignature = [self oauthSignatureForMethod:method URLString:URLString parameters:mutableParameters token:self.accessToken error:error];
    if (!oauthSignature) {
        return nil;
    }
    mutableAuthorizationParameters[@"oauth_signature"] = oauthSignature;
    
    NSArray *sortedQueryItems = [AFOAuth1Utils sortedQueryItemsFromParameters:mutableAuthorizationParameters];
    NSMutableArray *mutableComponents = [NSMutableArray array];
    for (NSArray *queryItem in sortedQueryItems) {
        if (queryItem.count == 2) {
            NSString *key = [AFOAuth1Utils percentEscapedQueryStringPairMemberFromString:queryItem[0] withEncoding:self.stringEncoding];
            NSString *value = [AFOAuth1Utils percentEscapedQueryStringPairMemberFromString:queryItem[1] withEncoding:self.stringEncoding];
            NSString *component = [NSString stringWithFormat:@"%@=\"%@\"", key, value];
            [mutableComponents addObject:component];
        }
    }
    
    return [NSString stringWithFormat:@"OAuth %@", [mutableComponents componentsJoinedByString:@", "]];
}

#pragma mark - 

- (NSMutableURLRequest *)requestWithMethod:(NSString *)method URLString:(NSString *)URLString parameters:(id)parameters error:(NSError *__autoreleasing *)error {
    NSMutableDictionary *mutableParameters = [parameters mutableCopy];
    for (NSString *key in parameters) {
        if ([key hasPrefix:@"oauth_"]) {
            [mutableParameters removeObjectForKey:key];
        }
    }
    
    NSMutableURLRequest *request = [super requestWithMethod:method URLString:URLString parameters:mutableParameters error:error];
    if (!request) {
        return nil;
    }
    
    // Only use parameters in the request entity body (with a content-type of `application/x-www-form-urlencoded`).
    // See RFC 5849, Section 3.4.1.3.1 http://tools.ietf.org/html/rfc5849#section-3.4
    NSDictionary *authorizationParameters = parameters;
    if (!([method isEqualToString:@"GET"] || [method isEqualToString:@"HEAD"] || [method isEqualToString:@"DELETE"])) {
        authorizationParameters = ([[request valueForHTTPHeaderField:@"Content-Type"] hasPrefix:@"application/x-www-form-urlencoded"] ? parameters : nil);
    }
    
    NSString *authorizationHeader = [self authorizationHeaderForMethod:method URLString:URLString parameters:authorizationParameters error:error];
    if (!authorizationHeader) {
        return nil;
    }
    [request setValue:authorizationHeader forHTTPHeaderField:@"Authorization"];
    [request setHTTPShouldHandleCookies:NO];
    
    return request;
}

@end
