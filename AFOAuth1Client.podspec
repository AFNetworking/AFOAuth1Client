Pod::Spec.new do |s|
  s.name         = "AFOAuth1Client"
  s.version      = "0.0.1"
  s.summary      = "AFNetworking Extension for OAuth 1.0a Authentication"
  s.homepage     = "https://github.com/AFNetworking/AFOAuth1Client"
  s.license      = 'MIT'
  s.author       = { 'Mattt Thompson' => 'm@mattt.me' }
  s.source       = { :git => "https://github.com/AFNetworking/AFOAuth1Client.git", :commit => "8cad77182223f3c9d0856bb51e3b5c62a883a1ef" }
  s.platform     = :ios, '5.0'
  s.source_files = 'AFOAuth1Client.{h,m}'

  s.dependency 'AFNetworking', '0.10.0'

  s.ios.frameworks = 'Security'
  
  s.prefix_header_contents = <<-EOS
#ifdef __OBJC__
  #import <Security/Security.h>
#endif /* __OBJC__*/
EOS

end
