# react-native-rsa-native

A native implementation of RSA key generation and encryption/decryption, sign/verify.
Keychain implementation
This implementation specifically uses OAEP SHA256 with MGF1 Padding

## Support

iOS 10+
android 4.1+ (API 16)

## Status

Features: 
Generation, 
Encryption, 
Decryption, 

Not currently features:
Sign,
Verify

## Getting started

`$ yarn add https://github.com/Pseudonymous-coders/react-native-rsa-native`

### Automatic installation:

`$ react-native link react-native-rsa-native`

## iOS

In your React Native Xcode project, right click on your project and go 'Add Files to ...', then navigate to <your-project-root>/node_modules/react-native-rsa-native/ios and select the RNRSA.xcodeproj file. Then in the build settings for your target under 'Link Binary With Libraries', add libRNRSA.a.

## Usage

```

import {RSA, RSAKeychain} from 'react-native-rsa-native';

RSA.generateKeys(4096) // set key size
  .then(keys => {
    console.log('4096 private:', keys.private) // the private key
    console.log('4096 public:', keys.public) // the public key
  })

RSA.generate() 
  .then(keys => {
    console.log(keys.private) // the private key
    console.log(keys.public) // the public key
    RSA.encrypt('1234', keys.public)
      .then(encodedMessage => {
        RSA.decrypt(encodedMessage, keys.private)
          .then(message => {
            console.log(message);
          })
        })

    RSA.sign(secret, keys.private)
      .then(signature => {
        console.log(signature);

        RSA.verify(signature, secret, keys.public)
          .then(valid => {
            console.log(valid);
          })
        })
  })

// Example utilizing the keychain for private key secure storage

let keyTag = 'com.domain.mykey';
let secret = "secret message";

RSAKeychain.generate(keyTag)
  .then(keys => {
    console.log(keys.public);
    console.log(secret);

    return RSAKeychain.encrypt(secret, keyTag)
      .then(encodedMessage => {
        console.log(encodedMessage);

        RSAKeychain.decrypt(encodedMessage, keyTag)
          .then(message => {
            console.log(message);
          })
        })
  })
  .then(() => {
  return RSAKeychain.sign(secret, keyTag)
    .then(signature => {
      console.log('signature', signature);

      RSAKeychain.verify(signature, secret, keyTag)
        .then(valid => {
          console.log('verified', valid);
        })
      })
  })
  .then(() => {
    RSAKeychain.deletePrivateKey(keyTag)
    .then( success => {
      console.log('delete success', success)
    })
  });
```
Check out example App.js for a full example


## Credit

* Originally based on https://github.com/SamSaffron/react-native-key-pair
* iOS implementation [reference](https://developer.apple.com/library/content/documentation/Security/Conceptual/CertKeyTrustProgGuide/KeyRead.html#//apple_ref/doc/uid/TP40001358-CH222-SW1)


## Donate

ETH: 0xDc2F8D78098749EB3ECdF79Fe32Efda86fEEFc3c
