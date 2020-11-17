//
//  CtkProviderUtils.h
//  CtkProvider
//
//  Created on 10/22/20.
//

#ifndef CtkProviderUtils_h
#define CtkProviderUtils_h

NSString* GetAsHex(const unsigned char* buf, int len);
NSString* HashAndHex(NSData* data);
SecIdentityRef GetIdentity(NSString* pkcs12Url, NSString* password);
void AddItem(SecIdentityRef identity);

#endif /* CtkProviderUtils_h */
