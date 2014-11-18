//
//  AFOAuth1Utils.h
//  Twitter iOS Example Client
//
//  Created by Stan Chang Khin Boon on 15/11/14.
//  Copyright (c) 2014 Just a Dream. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface AFOAuth1Utils : NSObject

+ (NSString *)percentEscapedQueryStringPairMemberFromString:(NSString *)string withEncoding:(NSStringEncoding)encoding;

+ (NSString *)sortedQueryString:(NSString *)queryString;
+ (NSArray *)sortedQueryItemsFromQueryString:(NSString *)queryString;
+ (NSDictionary *)parametersFromQueryString:(NSString *)queryString;
+ (NSArray *)sortedQueryItemsFromParameters:(NSDictionary *)parameters;

+ (BOOL)isQueryStringValueTrue:(NSString *)value;

@end
