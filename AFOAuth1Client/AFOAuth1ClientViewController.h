// AFOAuth1ClientViewController.m
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

#import <UIKit/UIKit.h>
#import "AFOAuth1Client.h"

@protocol AFOAuth1ClientViewControllerDelegate <NSObject>

@optional
- (void)didGetAccessPermissionWithClient:(AFOAuth1Client*)client attributes:(NSDictionary*)attributes;

@end

@interface AFOAuth1ClientViewController : UIViewController <UIWebViewDelegate>

@property (nonatomic,strong) AFOAuth1Client*													client;
@property (nonatomic,assign) id<AFOAuth1ClientViewControllerDelegate>	delegate;

- (id)initWithBaseURL:(NSURL*)baseURL
									key:(NSString*)key
							 secret:(NSString*)secret
		 requestTokenPath:(NSString*)requestTokenPath
userAuthorizationPath:(NSString*)userAuthorizationPath
					callbackURL:(NSURL*)callbackURL
			accessTokenPath:(NSString*)accessTokenPath
				 accessMethod:(NSString*)accessMethod
								scope:(NSString*)scope;

@end
