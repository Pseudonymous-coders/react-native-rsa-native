#import "RSANative.h"
//#import "RSAFormatter.h"

// Code largely based on practices as defined by:
// https://developer.apple.com/library/content/documentation/Security/Conceptual/CertKeyTrustProgGuide/KeyRead.html#//apple_ref/doc/uid/TP40001358-CH222-SW1

typedef void (^SecKeyPerformBlock)(SecKeyRef key);

@interface RSANative ()
@property (nonatomic) NSString *keyTag;
@property (nonatomic) SecKeyRef publicKeyRef;
@property (nonatomic) SecKeyRef privateKeyRef;
@end

@implementation RSANative

// Found this amazing ANS1 encoding example from https://blog.wingsofhermes.org/?p=42
size_t encodeLength(unsigned char * buf, size_t length) {
    if(length < 128) {
        buf[0] = length;
        return 1;
    }
    
    size_t i = (length / 256) + 1;
    buf[0] = i + 0x80;
    for(size_t j = 0; j < i; ++j) {
        buf[i - j] = length & 0xFF;
        length = length >> 8;
    }
    
    return i + 1;
}

- (instancetype)initWithKeyTag:(NSString *)keyTag {
    self = [super init];
    if (self) {
        _keyTag = keyTag;
    }
    return self;
}

- (void)generate:(int)keySize {
    NSMutableDictionary *privateKeyAttributes = [NSMutableDictionary dictionary];

    if (self.keyTag) {
        NSData *tag = [self.keyTag dataUsingEncoding:NSUTF8StringEncoding];

        privateKeyAttributes[(id)kSecAttrIsPermanent] = @YES; // store in keychain
        privateKeyAttributes[(id)kSecAttrApplicationTag] = tag;
    }

	NSMutableDictionary *attributes = [[NSMutableDictionary alloc] init]; 
    [attributes setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [attributes setObject:[NSNumber numberWithInt:keySize] forKey:(__bridge id)kSecAttrKeySizeInBits];
	[attributes setObject:privateKeyAttributes forKey:(__bridge id)kSecPrivateKeyAttrs];

    CFErrorRef error = NULL;
    SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes, &error);

    if (!privateKey) {
        NSError *err = CFBridgingRelease(error);
        NSLog(@"%@", err);
    }

    if (!self.keyTag) { // no keychain being used, store reference to keys for later use
        _privateKeyRef = privateKey;
        _publicKeyRef = SecKeyCopyPublicKey(privateKey);
    }
}

/*- (NSString *) encodeANSIKey {
    static const unsigned char _encodedOID[15] = {
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
    };
    
    NSData *publicTag = [NSData dataWithBytes:PUBLIC_KEY_TAG length:strlen((const char *) PUBLIC_KEY_TAG)];
    
    NSMutableDictionary *publicKeyQuery = [[NSMutableDictionary alloc] init];
    [publicKeyQuery setObject:(id)kSecClassKey forKey:(id)kSecClass];
    [publicKeyQuery setObject:publicTag forKey:(id)kSecAttrApplicationTag];
    [publicKeyQuery setObject:(id)kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
    [publicKeyQuery setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnData];
    
    NSData *publicKeyBits;
    //OSStatus err = SecItemCopyMatching((CFDictionaryRef) publicKeyQuery, (CFTypeRef *)&publicKeyBits);
    
    return NULL;
}*/

- (void)deletePrivateKey {
    if (self.keyTag) {
        NSDictionary *getquery = @{ (id)kSecClass: (id)kSecClassKey,
                                    (id)kSecAttrApplicationTag: self.keyTag,
                                    (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
                                    };
        SecItemDelete((CFDictionaryRef)getquery);
    } else {
        self.privateKey = nil;
    }
}

- (NSString *)encodedPublicKey {
    if (self.keyTag) {
        __block NSString *encodedPublicKey = nil;

        [self performWithPublicKeyTag:self.keyTag block:^(SecKeyRef publicKey) {
            encodedPublicKey = [self externalRepresentationForPublicKey:publicKey];
        }];

        return encodedPublicKey;
    }

    return [self externalRepresentationForPublicKey:self.publicKeyRef];
}

- (NSString *)encodedPrivateKey {
    if (self.keyTag) {
        __block NSString *encodedPrivateKey = nil;

        [self performWithPrivateKeyTag:self.keyTag block:^(SecKeyRef privateKey) {
            encodedPrivateKey = [self externalRepresentationForPrivateKey:privateKey];
        }];

        return encodedPrivateKey;
    }

    return [self externalRepresentationForPrivateKey:self.privateKeyRef];
}

- (void)setPublicKey:(NSString *)publicKey {
    //publicKey = [RSAFormatter stripHeaders: publicKey];
    NSDictionary* options = @{(id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
                              (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPublic,
//                              (id)kSecAttrKeySizeInBits: @2048,
                              };
    CFErrorRef error = NULL;
    NSData *data = [[NSData alloc] initWithBase64EncodedString:publicKey options:NSDataBase64DecodingIgnoreUnknownCharacters];
    SecKeyRef key = SecKeyCreateWithData((__bridge CFDataRef)data,
                                         (__bridge CFDictionaryRef)options,
                                         &error);
    if (!key) {
        NSError *err = CFBridgingRelease(error);
        NSLog(@"%@", err);
    } else {
        _publicKeyRef = key;
    }
}

- (void)setPrivateKey:(NSString *)privateKey {
    //privateKey = [RSAFormatter stripHeaders: privateKey];

    NSDictionary* options = @{(id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
                              (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPrivate,
//                              (id)kSecAttrKeySizeInBits: @2048,
                              };
    CFErrorRef error = NULL;
    NSData *data = [[NSData alloc] initWithBase64EncodedString:privateKey options:NSDataBase64DecodingIgnoreUnknownCharacters];
    SecKeyRef key = SecKeyCreateWithData((__bridge CFDataRef)data,
                                         (__bridge CFDictionaryRef)options,
                                         &error);
    if (!key) {
        NSError *err = CFBridgingRelease(error);
        NSLog(@"%@", err);
    } else {
        _privateKeyRef = key;
    }
}

- (NSString *)encrypt64:(NSString*)message {
    NSData *data = [[NSData alloc] initWithBase64EncodedString:message options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSData *encrypted = [self _encrypt: data];
    return [encrypted base64EncodedStringWithOptions:0];
}

- (NSString *)encrypt:(NSString *)message {
    NSData *data = [message dataUsingEncoding:NSUTF8StringEncoding];
    //NSData *data = [[NSData alloc] initWithBase64EncodedString:message options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSData *encrypted = [self _encrypt: data];
    return [encrypted base64EncodedStringWithOptions:0];
}

- (NSData *)_encrypt:(NSData *)data {
    __block NSData *cipherText = nil;

    void(^encryptor)(SecKeyRef) = ^(SecKeyRef publicKey) {
        BOOL canEncrypt = SecKeyIsAlgorithmSupported(publicKey,
                                                     kSecKeyOperationTypeEncrypt,
                                                     kSecKeyAlgorithmRSAEncryptionOAEPSHA256);
        if (canEncrypt) {
            CFErrorRef error = NULL;
            cipherText = (NSData *)CFBridgingRelease(SecKeyCreateEncryptedData(publicKey,
                                                                               kSecKeyAlgorithmRSAEncryptionOAEPSHA256,
                                                                               (__bridge CFDataRef)data,
                                                                               &error));
            if (!cipherText) {
                NSError *err = CFBridgingRelease(error);
                NSLog(@"%@", err);
            }
        }
    };

    if (self.keyTag) {
        [self performWithPublicKeyTag:self.keyTag block:encryptor];
    } else {
        encryptor(self.publicKeyRef);
    }

    return cipherText;
}

- (NSString *)decrypt64:(NSString*)message {
    NSData *data = [[NSData alloc] initWithBase64EncodedString:message options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSData *decrypted = [self _decrypt: data];
    return [decrypted base64EncodedStringWithOptions:0];
}

- (NSString *)decrypt:(NSString *)message {
    NSData *data = [[NSData alloc] initWithBase64EncodedString:message options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSData *decrypted = [self _decrypt: data];
    //return [decrypted base64EncodedStringWithOptions:0];}
    return [[NSString alloc] initWithData:decrypted encoding:NSUTF8StringEncoding];
}

- (NSData *)_decrypt:(NSData *)data {
    __block NSData *clearText = nil;

    void(^decryptor)(SecKeyRef) = ^(SecKeyRef privateKey) {

        BOOL canDecrypt = SecKeyIsAlgorithmSupported(privateKey,
                                                     kSecKeyOperationTypeDecrypt,
                                                     kSecKeyAlgorithmRSAEncryptionOAEPSHA256);
        
        if (canDecrypt) {
            CFErrorRef error = NULL;
            clearText = (NSData *)CFBridgingRelease(SecKeyCreateDecryptedData(privateKey,
                                                                              kSecKeyAlgorithmRSAEncryptionOAEPSHA256,
                                                                              (__bridge CFDataRef)data,
                                                                              &error));
            if (!clearText) {
                NSError *err = CFBridgingRelease(error);
                NSLog(@"%@", err);
            }
        }
    };

    if (self.keyTag) {
        [self performWithPrivateKeyTag:self.keyTag block:decryptor];
    } else {
        decryptor(self.privateKeyRef);
    }

    return clearText;
}

- (NSString *)sign64:(NSString *)b64message {
    NSData *data = [[NSData alloc] initWithBase64EncodedString:b64message options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSString *encodedSignature = [self _sign: data];
    return encodedSignature;
}

- (NSString *)sign:(NSString *)message {
    NSData* data = [message dataUsingEncoding:NSUTF8StringEncoding];
    NSString *encodedSignature = [self _sign: data];
    return encodedSignature;
}

- (NSString *)_sign:(NSData *)messageBytes {
    __block NSString *encodedSignature = nil;

    void(^signer)(SecKeyRef) = ^(SecKeyRef privateKey) {
        SecKeyAlgorithm algorithm = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512;
        
        BOOL canSign = SecKeyIsAlgorithmSupported(privateKey,
                                                kSecKeyOperationTypeSign,
                                                algorithm);

        NSData* signature = nil;

        if (canSign) {
            CFErrorRef error = NULL;
            signature = (NSData*)CFBridgingRelease(SecKeyCreateSignature(privateKey,
                                                                         algorithm,
                                                                         (__bridge CFDataRef)messageBytes,
                                                                         &error));
            if (!signature) {
              NSError *err = CFBridgingRelease(error);
              NSLog(@"error: %@", err);
            }
        }

        encodedSignature = [signature base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    };

    if (self.keyTag) {
        [self performWithPrivateKeyTag:self.keyTag block:signer];
    } else {
        signer(self.privateKeyRef);
    }

    return encodedSignature;
}

- (BOOL)verify64:(NSString *)encodedSignature withMessage:(NSString *)b64message {
    NSData *messageBytes = [[NSData alloc] initWithBase64EncodedString:b64message options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSData *signatureBytes = [[NSData alloc] initWithBase64EncodedString:encodedSignature options:NSDataBase64DecodingIgnoreUnknownCharacters];
    return [self _verify: signatureBytes withMessage: messageBytes];
}

- (BOOL)verify:(NSString *)encodedSignature withMessage:(NSString *)message {
    NSData *messageBytes = [message dataUsingEncoding:NSUTF8StringEncoding];
    NSData *signatureBytes = [[NSData alloc] initWithBase64EncodedString:encodedSignature options:NSDataBase64DecodingIgnoreUnknownCharacters];
    return [self _verify: signatureBytes withMessage: messageBytes];
}

- (BOOL)_verify:(NSData *)signatureBytes withMessage:(NSData *)messageBytes {
    __block BOOL result = NO;

    void(^verifier)(SecKeyRef) = ^(SecKeyRef publicKey) {
        SecKeyAlgorithm algorithm = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512;

        BOOL canVerify = SecKeyIsAlgorithmSupported(publicKey,
                                                    kSecKeyOperationTypeVerify,
                                                    algorithm);

        if (canVerify) {
            CFErrorRef error = NULL;
            result = SecKeyVerifySignature(publicKey,
                                           algorithm,
                                           (__bridge CFDataRef)messageBytes,
                                           (__bridge CFDataRef)signatureBytes,
                                           &error);
            if (!result) {
                NSError *err = CFBridgingRelease(error);
                NSLog(@"error: %@", err);
            }
        }
    };

    if (self.keyTag) {
        [self performWithPublicKeyTag:self.keyTag block:verifier];
    } else {
        verifier(self.publicKeyRef);
    }

    return result;
}

- (void)performWithPrivateKeyTag:(NSString *)keyTag block:(SecKeyPerformBlock)performBlock {
    NSData *tag = [keyTag dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *getquery = @{ (id)kSecClass: (id)kSecClassKey,
                                (id)kSecAttrApplicationTag: tag,
                                (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
                                (id)kSecReturnRef: @YES,
                                };

    SecKeyRef key = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)getquery,
                                          (CFTypeRef *)&key);

    if (status != errSecSuccess) {
        NSLog(@"error accessing the key");
    } else {
        if (performBlock) { performBlock(key); }
        if (key) { CFRelease(key); }
    }
}

- (void)performWithPublicKeyTag:(NSString *)tag block:(SecKeyPerformBlock)performBlock {
    [self performWithPrivateKeyTag:tag block:^(SecKeyRef key) {
        SecKeyRef publicKey = SecKeyCopyPublicKey(key);

        if (performBlock) { performBlock(publicKey); }
        if (publicKey) { CFRelease(publicKey); }
    }];
}

- (NSString *) externalRepresentationForPublicKey:(SecKeyRef)key {
    NSData *keyData = [self dataForKey:key];
    unsigned char builder[15];
    NSMutableData * encKey = [[NSMutableData alloc] init];
    int bitstringEncLength;
    
    // When we get to the bitstring - how will we encode it?
    if  ([keyData length ] + 1  < 128 )
        bitstringEncLength = 1 ;
    else
        bitstringEncLength = (([keyData length ] +1 ) / 256 ) + 2 ;
    
    static const unsigned char encodedOID[15] = {
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
    };
    
    // Overall we have a sequence of a certain length
    builder[0] = 0x30;    // ASN.1 encoding representing a SEQUENCE
    // Build up overall size made up of -
    // size of OID + size of bitstring encoding + size of actual key
    size_t i = sizeof(encodedOID) + 2 + bitstringEncLength + [keyData length];
    size_t j = encodeLength(&builder[1], i);
    [encKey appendBytes:builder length:j +1];
    
    // First part of the sequence is the OID
    [encKey appendBytes:encodedOID length:sizeof(encodedOID)];
    
    // Now add the bitstring
    builder[0] = 0x03;
    j = encodeLength(&builder[1], [keyData length] + 1);
    builder[j+1] = 0x00;
    [encKey appendBytes:builder length:j + 2];
    
    // Now the actual key
    [encKey appendData:keyData];

    return [encKey base64EncodedStringWithOptions:0];
}

- (NSString *) externalRepresentationForPrivateKey:(SecKeyRef)key {
    NSData *keyData = [self dataForKey:key];
    return [keyData base64EncodedStringWithOptions:0];
}


- (NSData *)dataForKey:(SecKeyRef)key {
    CFErrorRef error = NULL;
    NSData * keyData = (NSData *)CFBridgingRelease(SecKeyCopyExternalRepresentation(key, &error));
    
    if (!keyData) {
        NSError *err = CFBridgingRelease(error);
        NSLog(@"%@", err);
    }
    
    return keyData;
}

@end
