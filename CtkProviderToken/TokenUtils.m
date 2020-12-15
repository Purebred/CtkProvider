//
//  TokenUtils.m
//  CtkProviderToken
//
//  Created on 10/19/20.
//

#import <Foundation/Foundation.h>
#include <CommonCrypto/CommonDigest.h>
#include "TokenUtils.h"

const char* g_logPrefix = "CtkProviderToken log";

/*
 GetPrivateKeyRef takes an NSString instance containing a label value. It searches the key
 chain for keys with kSecAttrLabel and returns a SecKeyRef is a match is found
 and nil if no match is found. The returned value should be freed with CFRelease.
 */
SecKeyRef GetPrivateKeyRef(NSString* label)
{
    NSMutableDictionary * query = [[NSMutableDictionary alloc] init];

    [query setObject:(id)kSecClassKey forKey:(id)kSecClass];
    [query setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnRef];
    [query setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnData];
    [query setObject:(id)@"Authenticate to use private key" forKey:(id)kSecUseOperationPrompt];
    [query setObject:label forKey:(id)kSecAttrLabel];

    CFTypeRef items = nil;
    OSStatus resultCode = SecItemCopyMatching((CFDictionaryRef)query, (CFTypeRef *)&items);
    if(errSecSuccess == resultCode)
    {
        CFDictionaryRef dict = (CFDictionaryRef)items;
        SecKeyRef privateKeyRef = (SecKeyRef)CFDictionaryGetValue(dict, kSecValueRef);
        CFRetain(privateKeyRef);
        CFRelease(items);
        return privateKeyRef;
    }
    else
    {
        NSLog(@"%s: SecItemCopyMatching failed for %@: %d", g_logPrefix, label, resultCode);
        return nil;
    }
}

/*
 GetCertificateRef takes an NSString instance containing a label value. It searches the key
 chain for certificates with kSecAttrLabel and returns a SecCertificateRef is a match is found
 and nil if no match is found. The returned value should be freed with CFRelease.
 */
SecCertificateRef GetCertificateRef(NSString* label)
{
    NSMutableDictionary * query = [[NSMutableDictionary alloc] init];

    [query setObject:(id)kSecClassCertificate forKey:(id)kSecClass];
    [query setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnRef];
    [query setObject:label forKey:(id)kSecAttrLabel];
    [query setObject:(id)kSecMatchLimitOne forKey:(id)kSecMatchItemList];

    SecCertificateRef certificateRef;
    OSStatus resultCode = SecItemCopyMatching((CFDictionaryRef)query, (CFTypeRef *)&certificateRef);
    if(errSecSuccess == resultCode)
    {
        return certificateRef;
    }
    else
    {
        NSLog(@"SecItemCopyMatching failed for %@: %d", label, resultCode);
        return nil;
    }
}

/*
 NeedToHashFirst interrogates TKTokenAlgorithm to see if it is one of the 15 "message"
 algorithm values defined in SecKey.h and returns true if so. In all other cases (presumably
 one of the 61 algorithm values defined in SecKey.h), it returns false. This will return true
 for EC algorithms that are not actually supported at present.
 */
bool NeedToHashFirst(TKTokenKeyAlgorithm * algorithm)
{
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA224])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePSSSHA1])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePSSSHA224])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePSSSHA256])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePSSSHA384])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePSSSHA512])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureMessageX962SHA1])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureMessageX962SHA224])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureMessageX962SHA256])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureMessageX962SHA384])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureMessageX962SHA512])
        return true;

    return false;
}

/*
 GetAlgorithmFromTKTokenKeyAlgorithm interrogates TKTokenAlgorithm to see if it is one of the 76
 algorithm values defined in SecKey.h and returns the value if so. Returns nil if not known.
 */
SecKeyAlgorithm GetAlgorithmFromTKTokenKeyAlgorithm(TKTokenKeyAlgorithm * algorithm)
{
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureRaw])
        return kSecKeyAlgorithmRSAEncryptionRaw;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw])
        return kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1])
        return kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA224])
        return kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA224;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256])
        return kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384])
        return kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512])
        return kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1])
        return kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA224])
        return kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA224;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256])
        return kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384])
        return kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512])
        return kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPSSSHA1])
        return kSecKeyAlgorithmRSASignatureDigestPSSSHA1;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPSSSHA224])
        return kSecKeyAlgorithmRSASignatureDigestPSSSHA224;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPSSSHA256])
        return kSecKeyAlgorithmRSASignatureDigestPSSSHA256;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPSSSHA384])
        return kSecKeyAlgorithmRSASignatureDigestPSSSHA384;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPSSSHA512])
        return kSecKeyAlgorithmRSASignatureDigestPSSSHA512;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePSSSHA1])
        return kSecKeyAlgorithmRSASignatureMessagePSSSHA1;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePSSSHA224])
        return kSecKeyAlgorithmRSASignatureMessagePSSSHA224;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePSSSHA256])
        return kSecKeyAlgorithmRSASignatureMessagePSSSHA256;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePSSSHA384])
        return kSecKeyAlgorithmRSASignatureMessagePSSSHA384;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePSSSHA512])
        return kSecKeyAlgorithmRSASignatureMessagePSSSHA512;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureRFC4754])
        return kSecKeyAlgorithmECDSASignatureRFC4754;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962])
        return kSecKeyAlgorithmECDSASignatureDigestX962;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA1])
        return kSecKeyAlgorithmECDSASignatureDigestX962SHA1;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA224])
        return kSecKeyAlgorithmECDSASignatureDigestX962SHA224;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA256])
        return kSecKeyAlgorithmECDSASignatureDigestX962SHA256;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA384])
        return kSecKeyAlgorithmECDSASignatureDigestX962SHA384;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA512])
        return kSecKeyAlgorithmECDSASignatureDigestX962SHA512;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureMessageX962SHA1])
        return kSecKeyAlgorithmECDSASignatureMessageX962SHA1;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureMessageX962SHA224])
        return kSecKeyAlgorithmECDSASignatureMessageX962SHA224;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureMessageX962SHA256])
        return kSecKeyAlgorithmECDSASignatureMessageX962SHA256;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureMessageX962SHA384])
        return kSecKeyAlgorithmECDSASignatureMessageX962SHA384;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureMessageX962SHA512])
        return kSecKeyAlgorithmECDSASignatureMessageX962SHA512;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionRaw])
        return kSecKeyAlgorithmRSAEncryptionRaw;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionPKCS1])
        return kSecKeyAlgorithmRSAEncryptionPKCS1;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA1])
        return kSecKeyAlgorithmRSAEncryptionOAEPSHA1;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA224])
        return kSecKeyAlgorithmRSAEncryptionOAEPSHA224;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA256])
        return kSecKeyAlgorithmRSAEncryptionOAEPSHA256;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA384])
        return kSecKeyAlgorithmRSAEncryptionOAEPSHA384;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA512])
        return kSecKeyAlgorithmRSAEncryptionOAEPSHA512;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA1AESGCM])
        return kSecKeyAlgorithmRSAEncryptionOAEPSHA1AESGCM;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA224AESGCM])
        return kSecKeyAlgorithmRSAEncryptionOAEPSHA224AESGCM;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA256AESGCM])
        return kSecKeyAlgorithmRSAEncryptionOAEPSHA256AESGCM;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA384AESGCM])
        return kSecKeyAlgorithmRSAEncryptionOAEPSHA384AESGCM;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA512AESGCM])
        return kSecKeyAlgorithmRSAEncryptionOAEPSHA512AESGCM;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionStandardX963SHA1AESGCM])
        return kSecKeyAlgorithmECIESEncryptionStandardX963SHA1AESGCM;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionStandardX963SHA224AESGCM])
        return kSecKeyAlgorithmECIESEncryptionStandardX963SHA224AESGCM;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM])
        return kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionStandardX963SHA384AESGCM])
        return kSecKeyAlgorithmECIESEncryptionStandardX963SHA384AESGCM;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionStandardX963SHA512AESGCM])
        return kSecKeyAlgorithmECIESEncryptionStandardX963SHA512AESGCM;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionCofactorX963SHA1AESGCM])
        return kSecKeyAlgorithmECIESEncryptionCofactorX963SHA1AESGCM;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionCofactorX963SHA224AESGCM])
        return kSecKeyAlgorithmECIESEncryptionCofactorX963SHA224AESGCM;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM])
        return kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionCofactorX963SHA384AESGCM])
        return kSecKeyAlgorithmECIESEncryptionCofactorX963SHA384AESGCM;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionCofactorX963SHA512AESGCM])
        return kSecKeyAlgorithmECIESEncryptionCofactorX963SHA512AESGCM;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA224AESGCM])
        return kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA224AESGCM;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM])
        return kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA384AESGCM])
        return kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA384AESGCM;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA512AESGCM])
        return kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA512AESGCM;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA224AESGCM])
        return kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA224AESGCM;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM])
        return kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA384AESGCM])
        return kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA384AESGCM;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA512AESGCM])
        return kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA512AESGCM;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeStandard])
        return kSecKeyAlgorithmECDHKeyExchangeStandard;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA1])
        return kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA1;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA224])
        return kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA224;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256])
        return kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA384])
        return kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA384;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA512])
        return kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA512;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeCofactor])
        return kSecKeyAlgorithmECDHKeyExchangeCofactor;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA1])
        return kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA1;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA224])
        return kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA224;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA256])
        return kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA256;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA384])
        return kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA384;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA512])
        return kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA512;
    
    NSLog(@"%s: unrecognized algorithm passed to GetAlgorithmFromTKTokenKeyAlgorithm: %@", g_logPrefix, algorithm);
    return nil;
}

/*
 GetAlgorithmStringFromTKTokenKeyAlgorithm interrogates TKTokenAlgorithm to see if it is one of the 76
 algorithm values defined in SecKey.h and returns a string representation of the value if so. Returns
 "unknown" if not known.
 */
NSString* GetAlgorithmStringFromTKTokenKeyAlgorithm(TKTokenKeyAlgorithm * algorithm)
{
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureRaw])
        return @"kSecKeyAlgorithmRSAEncryptionRaw";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw])
        return @"kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1])
        return @"kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA224])
        return @"kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA224";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256])
        return @"kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384])
        return @"kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512])
        return @"kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1])
        return @"kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA224])
        return @"kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA224";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256])
        return @"kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384])
        return @"kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512])
        return @"kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPSSSHA1])
        return @"kSecKeyAlgorithmRSASignatureDigestPSSSHA1";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPSSSHA224])
        return @"kSecKeyAlgorithmRSASignatureDigestPSSSHA224";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPSSSHA256])
        return @"kSecKeyAlgorithmRSASignatureDigestPSSSHA256";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPSSSHA384])
        return @"kSecKeyAlgorithmRSASignatureDigestPSSSHA384";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPSSSHA512])
        return @"kSecKeyAlgorithmRSASignatureDigestPSSSHA512";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePSSSHA1])
        return @"kSecKeyAlgorithmRSASignatureMessagePSSSHA1";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePSSSHA224])
        return @"kSecKeyAlgorithmRSASignatureMessagePSSSHA224";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePSSSHA256])
        return @"kSecKeyAlgorithmRSASignatureMessagePSSSHA256";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePSSSHA384])
        return @"kSecKeyAlgorithmRSASignatureMessagePSSSHA384";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePSSSHA512])
        return @"kSecKeyAlgorithmRSASignatureMessagePSSSHA512";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureRFC4754])
        return @"kSecKeyAlgorithmECDSASignatureRFC4754";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962])
        return @"kSecKeyAlgorithmECDSASignatureDigestX962";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA1])
        return @"kSecKeyAlgorithmECDSASignatureDigestX962SHA1";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA224])
        return @"kSecKeyAlgorithmECDSASignatureDigestX962SHA224";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA256])
        return @"kSecKeyAlgorithmECDSASignatureDigestX962SHA256";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA384])
        return @"kSecKeyAlgorithmECDSASignatureDigestX962SHA384";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA512])
        return @"kSecKeyAlgorithmECDSASignatureDigestX962SHA512";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureMessageX962SHA1])
        return @"kSecKeyAlgorithmECDSASignatureMessageX962SHA1";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureMessageX962SHA224])
        return @"kSecKeyAlgorithmECDSASignatureMessageX962SHA224";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureMessageX962SHA256])
        return @"kSecKeyAlgorithmECDSASignatureMessageX962SHA256";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureMessageX962SHA384])
        return @"kSecKeyAlgorithmECDSASignatureMessageX962SHA384";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureMessageX962SHA512])
        return @"kSecKeyAlgorithmECDSASignatureMessageX962SHA512";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionRaw])
        return @"kSecKeyAlgorithmRSAEncryptionRaw";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionPKCS1])
        return @"kSecKeyAlgorithmRSAEncryptionPKCS1";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA1])
        return @"kSecKeyAlgorithmRSAEncryptionOAEPSHA1";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA224])
        return @"kSecKeyAlgorithmRSAEncryptionOAEPSHA224";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA256])
        return @"kSecKeyAlgorithmRSAEncryptionOAEPSHA256";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA384])
        return @"kSecKeyAlgorithmRSAEncryptionOAEPSHA384";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA512])
        return @"kSecKeyAlgorithmRSAEncryptionOAEPSHA512";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA1AESGCM])
        return @"kSecKeyAlgorithmRSAEncryptionOAEPSHA1AESGCM";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA224AESGCM])
        return @"kSecKeyAlgorithmRSAEncryptionOAEPSHA224AESGCM";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA256AESGCM])
        return @"kSecKeyAlgorithmRSAEncryptionOAEPSHA256AESGCM";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA384AESGCM])
        return @"kSecKeyAlgorithmRSAEncryptionOAEPSHA384AESGCM";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA512AESGCM])
        return @"kSecKeyAlgorithmRSAEncryptionOAEPSHA512AESGCM";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionStandardX963SHA1AESGCM])
        return @"kSecKeyAlgorithmECIESEncryptionStandardX963SHA1AESGCM";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionStandardX963SHA224AESGCM])
        return @"kSecKeyAlgorithmECIESEncryptionStandardX963SHA224AESGCM";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM])
        return @"kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionStandardX963SHA384AESGCM])
        return @"kSecKeyAlgorithmECIESEncryptionStandardX963SHA384AESGCM";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionStandardX963SHA512AESGCM])
        return @"kSecKeyAlgorithmECIESEncryptionStandardX963SHA512AESGCM";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionCofactorX963SHA1AESGCM])
        return @"kSecKeyAlgorithmECIESEncryptionCofactorX963SHA1AESGCM";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionCofactorX963SHA224AESGCM])
        return @"kSecKeyAlgorithmECIESEncryptionCofactorX963SHA224AESGCM";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM])
        return @"kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionCofactorX963SHA384AESGCM])
        return @"kSecKeyAlgorithmECIESEncryptionCofactorX963SHA384AESGCM";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionCofactorX963SHA512AESGCM])
        return @"kSecKeyAlgorithmECIESEncryptionCofactorX963SHA512AESGCM";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA224AESGCM])
        return @"kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA224AESGCM";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM])
        return @"kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA384AESGCM])
        return @"kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA384AESGCM";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA512AESGCM])
        return @"kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA512AESGCM";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA224AESGCM])
        return @"kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA224AESGCM";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM])
        return @"kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA384AESGCM])
        return @"kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA384AESGCM";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA512AESGCM])
        return @"kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA512AESGCM";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeStandard])
        return @"kSecKeyAlgorithmECDHKeyExchangeStandard";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA1])
        return @"kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA1";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA224])
        return @"kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA224";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256])
        return @"kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA384])
        return @"kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA384";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA512])
        return @"kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA512";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeCofactor])
        return @"kSecKeyAlgorithmECDHKeyExchangeCofactor";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA1])
        return @"kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA1";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA224])
        return @"kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA224";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA256])
        return @"kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA256";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA384])
        return @"kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA384";
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA512])
        return @"kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA512";
    
    NSLog(@"%s: unrecognized algorithm passed to GetAlgorithmStringFromTKTokenKeyAlgorithm: %@", g_logPrefix, algorithm);
    return @"unknown";
}

/*
 GetPaddingForAlg interrogates TKTokenAlgorithm to determine which one of the 76
 algorithm values defined in SecKey.h and returns a SecPadding value indicating the
 corresponding padding scheme or kSecPaddingNone if no padding scheme is indicated.
 */
SecPadding GetPaddingForAlg(TKTokenKeyAlgorithm* algorithm)
{
    /*
     typedef CF_OPTIONS(uint32_t, SecPadding)
     {
         kSecPaddingNone      = 0,
         kSecPaddingPKCS1     = 1,
         kSecPaddingOAEP      = 2, // __OSX_UNAVAILABLE __IOS_AVAILABLE(2.0) __TVOS_AVAILABLE(10.0) __WATCHOS_AVAILABLE(3.0),

         // For SecKeyRawSign/SecKeyRawVerify only,
         // ECDSA signature is raw byte format {r,s}, big endian.
         // First half is r, second half is s
         kSecPaddingSigRaw  = 0x4000,

         // For SecKeyRawSign/SecKeyRawVerify only, data to be signed is an MD2
         //   hash; standard ASN.1 padding will be done, as well as PKCS1 padding
         //  of the underlying RSA operation.
         kSecPaddingPKCS1MD2  = 0x8000, // __OSX_DEPRECATED(10.0, 10.12, "MD2 is deprecated") __IOS_DEPRECATED(2.0, 5.0, "MD2 is deprecated") __TVOS_UNAVAILABLE __WATCHOS_UNAVAILABLE,

         // For SecKeyRawSign/SecKeyRawVerify only, data to be signed is an MD5
         //   hash; standard ASN.1 padding will be done, as well as PKCS1 padding
         //   of the underlying RSA operation.
         kSecPaddingPKCS1MD5  = 0x8001, // __OSX_DEPRECATED(10.0, 10.12, "MD5 is deprecated") __IOS_DEPRECATED(2.0, 5.0, "MD5 is deprecated") __TVOS_UNAVAILABLE __WATCHOS_UNAVAILABLE,

         // For SecKeyRawSign/SecKeyRawVerify only, data to be signed is a SHA1
         //   hash; standard ASN.1 padding will be done, as well as PKCS1 padding
         //   of the underlying RSA operation.
         kSecPaddingPKCS1SHA1 = 0x8002,
         
         // For SecKeyRawSign/SecKeyRawVerify only, data to be signed is a SHA224
         // hash; standard ASN.1 padding will be done, as well as PKCS1 padding
         // of the underlying RSA operation.
         kSecPaddingPKCS1SHA224 = 0x8003, // __OSX_UNAVAILABLE __IOS_AVAILABLE(2.0),

         // For SecKeyRawSign/SecKeyRawVerify only, data to be signed is a SHA256
         // hash; standard ASN.1 padding will be done, as well as PKCS1 padding
         // of the underlying RSA operation.
         kSecPaddingPKCS1SHA256 = 0x8004, // __OSX_UNAVAILABLE __IOS_AVAILABLE(2.0),

         // For SecKeyRawSign/SecKeyRawVerify only, data to be signed is a SHA384
         // hash; standard ASN.1 padding will be done, as well as PKCS1 padding
         // of the underlying RSA operation.
         kSecPaddingPKCS1SHA384 = 0x8005, // __OSX_UNAVAILABLE __IOS_AVAILABLE(2.0),

         // For SecKeyRawSign/SecKeyRawVerify only, data to be signed is a SHA512
         // hash; standard ASN.1 padding will be done, as well as PKCS1 padding
         // of the underlying RSA operation.
         kSecPaddingPKCS1SHA512 = 0x8006, // __OSX_UNAVAILABLE __IOS_AVAILABLE(2.0),
     };
     */
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureRaw])
        return kSecPaddingPKCS1;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw])
        return kSecPaddingPKCS1;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1])
        return kSecPaddingPKCS1SHA1;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA224])
        return kSecPaddingPKCS1SHA224;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256])
        return kSecPaddingPKCS1SHA256;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384])
        return kSecPaddingPKCS1SHA384;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512])
        return kSecPaddingPKCS1SHA512;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1])
        return kSecPaddingPKCS1SHA1;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA224])
        return kSecPaddingPKCS1SHA224;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256])
        return kSecPaddingPKCS1SHA256;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384])
        return kSecPaddingPKCS1SHA384;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512])
        return kSecPaddingPKCS1SHA512;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPSSSHA1])
        return kSecPaddingPKCS1SHA1;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPSSSHA224])
        return kSecPaddingPKCS1SHA224;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPSSSHA256])
        return kSecPaddingPKCS1SHA256;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPSSSHA384])
        return kSecPaddingPKCS1SHA384;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPSSSHA512])
        return kSecPaddingPKCS1SHA512;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePSSSHA1])
        return kSecPaddingPKCS1SHA1;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePSSSHA224])
        return kSecPaddingPKCS1SHA224;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePSSSHA256])
        return kSecPaddingPKCS1SHA256;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePSSSHA384])
        return kSecPaddingPKCS1SHA384;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePSSSHA512])
        return kSecPaddingPKCS1SHA512;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionRaw])
        return kSecPaddingNone;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionPKCS1])
        return kSecPaddingPKCS1;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA1])
        return kSecPaddingOAEP;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA224])
        return kSecPaddingOAEP;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA256])
        return kSecPaddingOAEP;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA384])
        return kSecPaddingOAEP;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA512])
        return kSecPaddingOAEP;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA1AESGCM])
        return kSecPaddingOAEP;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA224AESGCM])
        return kSecPaddingOAEP;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA256AESGCM])
        return kSecPaddingOAEP;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA384AESGCM])
        return kSecPaddingOAEP;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA512AESGCM])
        return kSecPaddingOAEP;

    return kSecPaddingNone;
}

/*
 GetOperationStringFromTkTokenOperation interrogates a TKTokenOperation to determine
 the type of operation and returns a string representation of its findings.
 */
NSString* GetOperationStringFromTkTokenOperation(TKTokenOperation operation)
{
    if(TKTokenOperationNone == operation)
        return @"TKTokenOperationNone";
    else if(TKTokenOperationReadData == operation)
        return @"TKTokenOperationReadData";
    else if(TKTokenOperationSignData == operation)
        return @"TKTokenOperationSignData";
    else if(TKTokenOperationDecryptData == operation)
        return @"TKTokenOperationDecryptData";
    else if(TKTokenOperationPerformKeyExchange == operation)
        return @"TKTokenOperationPerformKeyExchange";
    else
        return @"Unknown TKTokenOperation";
}

/*
 GetAlgorithmFromTKTokenKeyAlgorithm interrogates TKTokenAlgorithm to determine which one of the 76
 algorithm values defined in SecKey.h and returns a SupportedHashAlg enum value indicating the
 corresponding hash algorithm or CTK_UNKNOWN if no hash algorithm is indicated.
 */
enum SupportedHashAlg GetHashAlgFromTkTokenKeyAlgorithm(TKTokenKeyAlgorithm * algorithm)
{
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureRaw])
        return CTK_UNKNOWN;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw])
        return CTK_UNKNOWN;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1])
        return CTK_SHA1;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA224])
        return CTK_SHA224;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256])
        return CTK_SHA256;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384])
        return CTK_SHA384;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512])
        return CTK_SHA512;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1])
        return CTK_SHA1;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA224])
        return CTK_SHA224;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256])
        return CTK_SHA256;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384])
        return CTK_SHA384;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512])
        return CTK_SHA512;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPSSSHA1])
        return CTK_SHA1;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPSSSHA224])
        return CTK_SHA224;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPSSSHA256])
        return CTK_SHA256;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPSSSHA384])
        return CTK_SHA384;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPSSSHA512])
        return CTK_SHA512;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePSSSHA1])
        return CTK_SHA1;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePSSSHA224])
        return CTK_SHA224;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePSSSHA256])
        return CTK_SHA256;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePSSSHA384])
        return CTK_SHA384;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePSSSHA512])
        return CTK_SHA512;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureRFC4754])
        return CTK_UNKNOWN;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962])
        return CTK_UNKNOWN;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA1])
        return CTK_SHA1;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA224])
        return CTK_SHA224;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA256])
        return CTK_SHA256;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA384])
        return CTK_SHA384;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA512])
        return CTK_SHA512;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureMessageX962SHA1])
        return CTK_SHA1;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureMessageX962SHA224])
        return CTK_SHA224;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureMessageX962SHA256])
        return CTK_SHA256;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureMessageX962SHA384])
        return CTK_SHA384;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureMessageX962SHA512])
        return CTK_SHA512;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionRaw])
        return CTK_UNKNOWN;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionPKCS1])
        return CTK_UNKNOWN;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA1])
        return CTK_SHA1;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA224])
        return CTK_SHA224;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA256])
        return CTK_SHA256;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA384])
        return CTK_SHA384;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA512])
        return CTK_SHA512;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA1AESGCM])
        return CTK_SHA1;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA224AESGCM])
        return CTK_SHA224;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA256AESGCM])
        return CTK_SHA256;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA384AESGCM])
        return CTK_SHA384;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA512AESGCM])
        return CTK_SHA512;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionStandardX963SHA1AESGCM])
        return CTK_SHA1;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionStandardX963SHA224AESGCM])
        return CTK_SHA224;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM])
        return CTK_SHA256;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionStandardX963SHA384AESGCM])
        return CTK_SHA384;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionStandardX963SHA512AESGCM])
        return CTK_SHA512;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionCofactorX963SHA1AESGCM])
        return CTK_SHA1;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionCofactorX963SHA224AESGCM])
        return CTK_SHA224;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM])
        return CTK_SHA256;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionCofactorX963SHA384AESGCM])
        return CTK_SHA384;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionCofactorX963SHA512AESGCM])
        return CTK_SHA512;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA224AESGCM])
        return CTK_SHA224;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM])
        return CTK_SHA256;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA384AESGCM])
        return CTK_SHA384;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA512AESGCM])
        return CTK_SHA512;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA224AESGCM])
        return CTK_SHA224;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM])
        return CTK_SHA256;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA384AESGCM])
        return CTK_SHA384;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA512AESGCM])
        return CTK_SHA512;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeStandard])
        return CTK_UNKNOWN;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA1])
        return CTK_SHA1;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA224])
        return CTK_SHA224;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256])
        return CTK_SHA256;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA384])
        return CTK_SHA384;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA512])
        return CTK_SHA512;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeCofactor])
        return CTK_UNKNOWN;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA1])
        return CTK_SHA1;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA224])
        return CTK_SHA224;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA256])
        return CTK_SHA256;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA384])
        return CTK_SHA384;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA512])
        return CTK_SHA512;
    
    return CTK_UNKNOWN;
}

/*
 IsAlgorithmSupported interrogates TKTokenAlgorithm to see if it is one of the 34 RSA
 algorithm values defined in SecKey.h and returns true if so. In all other cases (presumably
 one of the 42 EC algorithm values defined in SecKey.h), it returns false.
 */
bool IsAlgorithmSupported(TKTokenKeyAlgorithm * algorithm)
{
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureRaw])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA224])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA224])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512])
        return true;
 /*
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPSSSHA1])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPSSSHA224])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPSSSHA256])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPSSSHA384])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureDigestPSSSHA512])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePSSSHA1])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePSSSHA224])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePSSSHA256])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePSSSHA384])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureMessagePSSSHA512])
        return true;
        */
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionRaw])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionPKCS1])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA1])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA224])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA256])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA384])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA512])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA1AESGCM])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA224AESGCM])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA256AESGCM])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA384AESGCM])
        return true;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA512AESGCM])
        return true;

    return false;
}
