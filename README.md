# AFOAuth1Client

> _This is still in early stages of development, so proceed with caution when using this in a production application.  
> Any bug reports, feature requests, or general feedback at this point would be greatly appreciated._

## Instructions

Add all of the included files into an iOS project with AFNetworking. `AFHTTPClient` should replace the existing copy in your current AFNetworking installation.

Register your application to [launch from a custom URL scheme](http://iphonedevelopertips.com/cocoa/launching-your-own-application-via-a-custom-url-scheme.html), and use that with the path `/success` as your callback URL.

Here's how it all looks together:

``` objective-c
AFOAuth1Client *twitterClient = [[AFOAuth1Client alloc] initWithBaseURL:[NSURL URLWithString:@"https://api.twitter.com/"] clientKey:@"..." clientSecret:@"..."];
    
// Your application will be sent to the background until the user authenticates, and then the app will be brought back using the callback URL
[twitterClient authorizeUsingOAuthWithRequestTokenPath:@"oauth/request_token" userAuthorizationPath:@"oauth/authorize" callbackURL:[NSURL URLWithString:@"x-com-YOUR-APP-SCHEME://success"] accessTokenPath:@"oauth/access_token" success:^(AFOAuth1Token *accessToken) {
    NSLog(@"Success: %@", accessToken);
} failure:^(NSError *error) {
    NSLog(@"Error: %@", error);
}];
```
Remeber to handle the callback in your application delegate

``` objective-c
-(BOOL)application:(UIApplication *)application handleOpenURL:(NSURL *)url {
    return [twitterClient handleURL:url];
}
-(BOOL)application:(UIApplication *)application openURL:(NSURL *)url sourceApplication:(NSString *)sourceApplication annotation:(id)annotation {
    return [twitterClient handleURL:url];
}
```

Create simple requests

``` objective-c
[self.twitterClient getOAuthPath:@"1/statuses/user_timeline.json" 
					  parameters:nil 
					     success:^(AFHTTPRequestOperation *operation, id responseObject) {
	                        NSArray *responseArray = (NSArray *)responseObject;
	                        [responseArray enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
	                            NSLog(@"obj: %@", obj);
	                        }];
                       } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
                       		NSLog(@"error: %@", error);
                       }];
```


## Contact

Mattt Thompson

- http://github.com/mattt
- http://twitter.com/mattt
- m@mattt.me

## License

AFOAuth1Client is available under the MIT license. See the LICENSE file for more info.
