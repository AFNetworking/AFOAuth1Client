# AFOAuth1Client

AFOAuth1Client is an extension for [AFNetworking](http://github.com/AFNetworking/AFNetworking/) that simplifies the process of authenticating against an [OAuth 1.0a](https://tools.ietf.org/html/rfc5849) provider.

## Usage

```objective-c
NSURL *baseURL = [NSURL URLWithString:@"https://twitter.com/oauth/"];
AFOAuth1Client *OAuth1Client = [[AFOAuth1Client alloc] initWithBaseURL:baseURL
                                                                   key:@"..."
                                                                secret:@"..."];
```

Register your application to [launch from a custom URL scheme](http://iphonedevelopertips.com/cocoa/launching-your-own-application-via-a-custom-url-scheme.html), and use that with the path `/success` as your callback URL.  The callback for the custom URL scheme should send a notification, which will complete the OAuth transaction.

```objective-c
NSURL *callbackURL = [NSURL URLWithString:@"x-com-YOUR-APP-SCHEME://success"];
[OAuth1Client authorizeUsingOAuthWithRequestTokenPath:@"/request_token"
                                userAuthorizationPath:@"/authorize"
                                          callbackURL:callbackURL
                                      accessTokenPath:@"/access_token"
                                              success:^(AFOAuth1Token *accessToken) {
                                                  NSLog(@"Success: %@", accessToken);
                                              }
                                              failure:^(NSError *error) {
                                                  NSLog(@"Error: %@", error);
                                              }];
```

Responding to the custom URL scheme on iOS:

```objective-c
- (BOOL)application:(UIApplication *)application
            openURL:(NSURL *)URL
  sourceApplication:(NSString *)sourceApplication
         annotation:(id)annotation
{
    NSNotification *notification =
        [NSNotification notificationWithName:kAFApplicationLaunchedWithURLNotification
                                      object:nil
                                    userInfo:@{kAFApplicationLaunchOptionsURLKey: URL}];
    [[NSNotificationCenter defaultCenter] postNotification:notification];

    return YES;
}
```

## Contact

Mattt Thompson

- http://github.com/mattt
- http://twitter.com/mattt
- m@mattt.me

## License

AFOAuth1Client is available under the MIT license. See the LICENSE file for more info.
