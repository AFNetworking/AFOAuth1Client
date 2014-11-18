//
//  AFOAuth1Utils.m
//  Twitter iOS Example Client
//
//  Created by Stan Chang Khin Boon on 15/11/14.
//  Copyright (c) 2014 Just a Dream. All rights reserved.
//

#import "AFOAuth1Utils.h"

@implementation AFOAuth1Utils

+ (NSString *)percentEscapedQueryStringPairMemberFromString:(NSString *)string withEncoding:(NSStringEncoding)encoding {
    static NSString * const kAFOAuth1CharactersToBeEscaped = @":/?&=;+!@#$()',*";
    static NSString * const kAFOAuth1CharactersToLeaveUnescaped = @"[].";
    return (__bridge_transfer NSString *)CFURLCreateStringByAddingPercentEscapes(kCFAllocatorDefault, (__bridge CFStringRef)string, (__bridge CFStringRef)kAFOAuth1CharactersToLeaveUnescaped, (__bridge CFStringRef)kAFOAuth1CharactersToBeEscaped, CFStringConvertNSStringEncodingToEncoding(encoding));
}

+ (NSString *)sortedQueryString:(NSString *)queryString {
    return [[[queryString componentsSeparatedByString:@"&"] sortedArrayUsingSelector:@selector(compare:)] componentsJoinedByString:@"&"];
}

+ (NSArray *)sortedQueryItemsFromQueryString:(NSString *)queryString {
    NSArray *sortedQueryPairs = [[queryString componentsSeparatedByString:@"&"] sortedArrayUsingSelector:@selector(compare:)];
    NSMutableArray *sortedQueryItems = [[NSMutableArray alloc] init];
    for (NSString *queryPair in sortedQueryPairs) {
        NSArray *queryItem = [queryPair componentsSeparatedByString:@"="];
        [sortedQueryItems addObject:queryItem];
    }
    return sortedQueryItems;
}

+ (NSDictionary *)parametersFromQueryString:(NSString *)queryString {
    NSArray *sortedQueryItems = [self sortedQueryItemsFromQueryString:queryString];
    NSMutableDictionary *parameters = [[NSMutableDictionary alloc] init];
    for (NSArray *queryItem in sortedQueryItems) {
        switch (queryItem.count) {
            case 1: {
                NSString *key = queryItem[0];
                parameters[key] = [NSNull null];
            } break;
            case 2: {
                NSString *key = queryItem[0];
                NSString *value = queryItem[1];
                parameters[key] = value;
            } break;
            default: {
                NSLog(@"Ignoring query item:\n%@", queryItem);
            } break;
        }
    }
    return parameters;
}

// FIXME: (me@lxcid.com) No support for nested parameters.
+ (NSArray *)sortedQueryItemsFromParameters:(NSDictionary *)parameters {
    NSMutableArray *queryItems = [NSMutableArray array];
    [parameters enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
        [queryItems addObject:@[ key, obj ]];
    }];
    NSSortDescriptor *firstObjectSortDescriptor = [NSSortDescriptor sortDescriptorWithKey:@"firstObject" ascending:YES selector:@selector(compare:)];
    [queryItems sortUsingDescriptors:@[ firstObjectSortDescriptor ]];
    return [queryItems copy];
}

+ (BOOL)isQueryStringValueTrue:(NSString *)value {
    return value && [value.lowercaseString hasPrefix:@"t"];
}

@end
