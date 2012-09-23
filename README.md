# AFOAuth1Client

> _This is still in early stages of development, so proceed with caution when using this in a production application.  
> Any bug reports, feature requests, or general feedback at this point would be greatly appreciated._

## Instructions

Add all of the included files into an iOS project with AFNetworking. `AFHTTPClient` should replace the existing copy in your current AFNetworking installation.

Register your application to [launch from a custom URL scheme](http://iphonedevelopertips.com/cocoa/launching-your-own-application-via-a-custom-url-scheme.html), and use that with the path `/success` as your callback URL.

Here's how it all looks together:

``` objective-c
AFOAuth1Client *twitterClient = [[[AFOAuth1Client alloc] initWithBaseURL:[NSURL URLWithString:@"https://twitter.com/oauth/"] key:@"..." secret:@"..."] autorelease];
    
// Your application will be sent to the background until the user authenticates, and then the app will be brought back using the callback URL
[twitterClient authorizeUsingOAuthWithRequestTokenPath:@"/request_token" userAuthorizationPath:@"/authorize" callbackURL:[NSURL URLWithString:@"x-com-YOUR-APP-SCHEME://success"] accessTokenPath:@"/access_token" success:^(AFOAuth1Token *accessToken) {
    NSLog(@"Success: %@", accessToken);
    NSLog(@"Your OAuth credentials are now set in the `Authorization` HTTP header");
} failure:^(NSError *error) {
    NSLog(@"Error: %@", error);
}];
```

## Contact

Mattt Thompson

- http://github.com/mattt
- http://twitter.com/mattt
- m@mattt.me

## License

AFOAuth1Client is available under the MIT license. See the LICENSE file for more info.
