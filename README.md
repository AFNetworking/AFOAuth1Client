# AFOAuth1Client

## Instructions

Register your application to [launch from a custom URL scheme](http://iphonedevelopertips.com/cocoa/launching-your-own-application-via-a-custom-url-scheme.html), and use that with the path `success` as your callback URL.  The callback for the custom URL scheme should send a notification, which will complete the OAuth transaction.

Here's how to create a client and authenticate:

Objective-C
<pre>
AFOAuth1Client *twitterClient = [[AFOAuth1Client alloc] initWithBaseURL:[NSURL URLWithString:@"https://api.twitter.com/1.1/"] key:@"..." secret:@"..."];

// Your application will be sent to the background until the user authenticates, and then the app will be brought back using the callback URL
[self.twitterClient authorizeUsingOAuthWithRequestTokenPath:@"/oauth/request_token" userAuthorizationPath:@"/oauth/authorize" callbackURL:[NSURL URLWithString:@"af-twitter://success"] accessTokenPath:@"/oauth/access_token" accessMethod:@"POST" scope:nil success:^(AFOAuth1Token *accessToken, id responseObject) {
	NSMutableURLRequest *request = [self.twitterClient requestWithMethod:@"GET" path:@"statuses/user_timeline.json" parameters:nil];
	AFHTTPRequestOperationManager *manager = [AFHTTPRequestOperationManager manager];
	AFHTTPRequestOperation *operation = [[AFHTTPRequestOperationManager manager] HTTPRequestOperationWithRequest:request success:^(AFHTTPRequestOperation *operation, id responseObject) {
		NSLog(@"Success: %@", responseObject);
	} failure:^(AFHTTPRequestOperation *operation, NSError *error) {
		NSLog(@"Error: %@", [error localizedDescription]);
	}];
	[manager.operationQueue addOperation:operation];
} failure:^(NSError *error) {
	NSLog(@"Error: %@", error);
}];
</pre>

Here's how to respond to the custom URL scheme on iOS: 

Objective-C
<pre>
- (BOOL)application:(UIApplication *)application openURL:(NSURL *)url sourceApplication:(NSString *)sourceApplication annotation:(id)annotation
{
	NSNotification *notification = [NSNotification notificationWithName:kAFApplicationLaunchedWithURLNotification object:nil userInfo:[NSDictionary dictionaryWithObject:url forKey:kAFApplicationLaunchOptionsURLKey]];
	[[NSNotificationCenter defaultCenter] postNotification:notification];

	return YES;
}
</pre>

## Contact

Joel Chen

http://lnkd.in/bwwnBWR

## License

AFOAuth1Client is available under the MIT license. See the LICENSE file for more info.
