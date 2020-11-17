//
//  Token.h
//  CtkProviderToken
//
//  Created by on 10/16/20.
//

#import <CryptoTokenKit/CryptoTokenKit.h>

@interface TokenDriver : TKTokenDriver<TKTokenDriverDelegate>

@end

@interface TokenSession : TKTokenSession<TKTokenSessionDelegate>

@end

@interface Token : TKToken<TKTokenDelegate>

@end
