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

#import "AFOAuth1ClientViewController.h"

@interface AFOAuth1ClientViewController()

@property (nonatomic,strong) UIWebView* webView;
@property (nonatomic,strong) NSString*	accessTokenPath;
@property (nonatomic,strong) NSString*	accessMethod;

@end

@implementation AFOAuth1ClientViewController

- (id)initWithBaseURL:(NSURL*)baseURL
									key:(NSString*)key
							 secret:(NSString*)secret
		 requestTokenPath:(NSString*)requestTokenPath
userAuthorizationPath:(NSString*)userAuthorizationPath
					callbackURL:(NSURL*)callbackURL
			accessTokenPath:(NSString*)accessTokenPath
				accessMethod:(NSString*)accessMethod
												 scope:(NSString*)scope
{
	self = [super init];
	if (self) {
		self.client = [[AFOAuth1Client alloc]initWithBaseURL:baseURL key:key secret:secret];
		self.accessMethod = accessMethod;
		self.accessTokenPath = accessTokenPath;
		[self.client acquireOAuthRequestTokenWithPath:requestTokenPath callbackURL:callbackURL accessMethod:accessMethod scope:scope success:^(AFOAuth1Token *requestToken, id responseObject) {
			if (self.view != nil) {
				NSString* url = [NSString stringWithFormat:@"%@%@?oauth_token=%@",baseURL,userAuthorizationPath,requestToken.key];
				[self.webView loadRequest:[NSURLRequest requestWithURL:[NSURL URLWithString:url]]];
			}
			[self.client setAccessToken:requestToken];
		} failure:^(NSError *error) {
			NSLog(@"Cannot get Access Request from the server");
		}];
		
	}
	return self;
}

- (void)webViewDidFinishLoad:(UIWebView *)webView
{
	NSString* urlString = [[webView.request URL]absoluteString];
	if ([urlString rangeOfString:@"oauth_verifier"].location != NSNotFound) {
		NSString* verifier = [[urlString componentsSeparatedByString:@"="]lastObject];
		self.client.accessToken.verifier = verifier;
		[self getAccessToken];
		[self dismissViewControllerAnimated:YES completion:nil];
	}
}

- (void)getAccessToken
{
	[self.client acquireOAuthAccessTokenWithPath:self.accessTokenPath requestToken:self.client.accessToken accessMethod:self.accessMethod success:^(AFOAuth1Token *accessToken, id responseObject) {
		self.client.accessToken = accessToken;
		[self.delegate didGetAccessPermissionWithClient:self.client attributes:[self.client parametersFromResponseObject:responseObject]];
	} failure:^(NSError *error) {
		NSLog(@"%@",error);
	}];
}

- (id)initWithNibName:(NSString *)nibNameOrNil bundle:(NSBundle *)nibBundleOrNil
{
    self = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil];
    if (self) {
        // Custom initialization
    }
    return self;
}

- (void)loadView
{
	[super loadView];
	self.webView = [[UIWebView alloc]initWithFrame:self.view.frame];
	[self.webView setDelegate:self];
	[self.webView setScalesPageToFit:YES];
	[self.view addSubview:self.webView];
}

- (void)didReceiveMemoryWarning
{
	[super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
