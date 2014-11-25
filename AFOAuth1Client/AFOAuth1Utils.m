// AFOAuth1Utils.m
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
    [queryItems sortUsingComparator:^NSComparisonResult(NSArray *queryItem1, NSArray *queryItem2) {
        id key1 = queryItem1.firstObject;
        id key2 = queryItem2.firstObject;
        return [key1 compare:key2];
    }];
    return [queryItems copy];
}

+ (BOOL)isQueryStringValueTrue:(NSString *)value {
    return value && [value.lowercaseString hasPrefix:@"t"];
}

@end
