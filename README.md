<!--
This README describes the package. If you publish this package to pub.dev,
this README's contents appear on the landing page for your package.

For information about how to write a good package README, see the guide for
[writing package pages](https://dart.dev/guides/libraries/writing-package-pages).

For general information about developing packages, see the Dart guide for
[creating packages](https://dart.dev/guides/libraries/create-library-packages)
and the Flutter guide for
[developing packages and plugins](https://flutter.dev/developing-packages).
-->

A Flutter HD Wallet package which provides 
implementation of Hierarchical Deterministic Wallets [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki),
Mnemonic code for generating deterministic keys [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki),
and Multi-Account Hierarchy for Deterministic Wallets [BIP44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki).

Inspired by [hd-wallet-kit-android](https://github.com/horizontalsystems/hd-wallet-kit-android)

## Features

### Mnemonic
* Generate mnemonic
* From mnemonic to seed

### HD Wallet
* Create HD wallet from seed
* Key derivation by path
* Key derivation by purpose, coinType, account, change, and index.
* Key serialization

### Support wordlists
* [English](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt)
* [Japanese](https://github.com/bitcoin/bips/blob/master/bip-0039/japanese.txt)
* [Korean](https://github.com/bitcoin/bips/blob/master/bip-0039/korean.txt)
* [Spanish](https://github.com/bitcoin/bips/blob/master/bip-0039/spanish.txt)
* [Chinese (Simplified)](https://github.com/bitcoin/bips/blob/master/bip-0039/chinese_simplified.txt)
* [Chinese (Traditional)](https://github.com/bitcoin/bips/blob/master/bip-0039/chinese_traditional.txt)
* [French](https://github.com/bitcoin/bips/blob/master/bip-0039/french.txt)
* [Italian](https://github.com/bitcoin/bips/blob/master/bip-0039/italian.txt)
* [Czech](https://github.com/bitcoin/bips/blob/master/bip-0039/czech.txt)
* [Portuguese](https://github.com/bitcoin/bips/blob/master/bip-0039/portuguese.txt)

## Getting started

To use this plugin, add `hd_wallet_kit` as a [dependency in your pubspec.yaml file](https://flutter.dev/platform-plugins/).

## Usage

Generate mnemonic:
```dart
final mnemonic = Mnemonic.generate();
```

From mnemonic to seed:
```dart
final seed = Mnemonic.toSeed(mnemonic);
```

Create hd wallet from seed:
```dart
final hdWallet = HDWallet.fromSeed(seed: seed);
```

Key derivation:
```dart
final key = hdWallet.getPrivateKeyByPath("m/0");
final bip44Key = hdWallet.getPrivateKey(purpose: Purpose.BIP44, coinType: 0, account: 0, change: 0, index: 0);
```
