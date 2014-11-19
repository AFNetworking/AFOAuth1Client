//
//  AFOAuth1RequestSerializer.h
//  
//
//  Created by Stan Chang Khin Boon on 12/11/14.
//
//

#import "AFURLRequestSerialization.h"

@class AFOAuth1Token;

typedef NS_ENUM(NSUInteger, AFOAuth1SignatureMethod) {
    AFOAuth1PlainTextSignatureMethod = 1,
    AFOAuth1HMACSHA1SignatureMethod = 2,
};

@interface AFOAuth1RequestSerializer : AFHTTPRequestSerializer

///-----------------------------------
/// @name Managing OAuth Configuration
///-----------------------------------

/**
 
 */
@property (nonatomic, assign) AFOAuth1SignatureMethod signatureMethod;

/**
 
 */
@property (nonatomic, copy) NSString *realm;

/**
 
 */
@property (nonatomic, strong) AFOAuth1Token *accessToken;

/**
 
 */
@property (nonatomic, copy) NSString *oauthAccessMethod;

/**
 
 */
@property (nonatomic, copy, readonly) NSDictionary *oauthParameters;

+ (instancetype)serializerWithKey:(NSString *)key secret:(NSString *)secret;

@end
