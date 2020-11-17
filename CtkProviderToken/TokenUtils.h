//
//  TokenUtils.h
//  CtkProvider
//
//  Created by 10/19/20.
//

#ifndef TokenUtils_h
#define TokenUtils_h

#import <CryptoTokenKit/CryptoTokenKit.h>

extern const char* g_logPrefix;

enum SupportedHashAlg {
    CTK_UNKNOWN = 0,
    CTK_SHA1 = 1,
    CTK_SHA224 = 2,
    CTK_SHA256 = 3,
    CTK_SHA384 = 4,
    CTK_SHA512 = 5
};

SecKeyRef GetPrivateKeyRef(NSString* label);
SecCertificateRef GetCertificateRef(NSString* label);
SecKeyAlgorithm GetAlgorithmFromTKTokenKeyAlgorithm(TKTokenKeyAlgorithm * algorithm);
NSString* GetAlgorithmStringFromTKTokenKeyAlgorithm(TKTokenKeyAlgorithm * algorithm);
NSString* GetOperationStringFromTkTokenOperation(TKTokenOperation operation);
SecPadding GetPaddingForAlg(TKTokenKeyAlgorithm* algorithm);
bool NeedToHashFirst(TKTokenKeyAlgorithm * algorithm);
enum SupportedHashAlg GetHashAlgFromTkTokenKeyAlgorithm(TKTokenKeyAlgorithm * algorithm);
bool IsAlgorithmSupported(TKTokenKeyAlgorithm * algorithm);

#endif /* TokenUtils_h */
