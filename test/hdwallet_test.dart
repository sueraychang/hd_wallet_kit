import 'dart:typed_data';

import 'package:base58check/base58check.dart';
import 'package:convert/convert.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hd_wallet_kit/src/base58.dart';
import 'package:hd_wallet_kit/src/hdextendedkey.dart';
import 'package:hd_wallet_kit/src/hdextendedkeyversion.dart';
import 'package:hd_wallet_kit/src/hdwallet.dart';
import 'package:hd_wallet_kit/src/hdwalletkitexception.dart';
import 'package:hd_wallet_kit/src/mnemonic.dart';
import 'package:hd_wallet_kit/utils.dart';

void main() {
  String wifCompressed(Uint8List privateKey) {
    final builder = BytesBuilder();
    builder.addByte(0x80);
    builder.add(privateKey.sublist(privateKey.length - 32, privateKey.length));
    builder.addByte(0x01);
    final doubleSHA256 = doubleSHA256Digest(builder.toBytes());
    final addrChecksum = doubleSHA256.sublist(0, 4);
    return base58codec.encode(builder.toBytes() + addrChecksum);
  }

  String address(Uint8List pubKeyHash) {
    return base58checkCodec.encode(Base58CheckPayload(0, pubKeyHash));
  }

  final mnemonic =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
          .split(' ');
  final seed = Mnemonic.toSeed(mnemonic);
  final hdWallet = HDWallet.fromSeed(seed: seed);

  final testVector1 = hexStringToUint8List('000102030405060708090a0b0c0d0e0f');
  final vector1Wallet = HDWallet.fromSeed(seed: testVector1);

  final testVector2 = hexStringToUint8List(
      'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542');
  final vector2Wallet = HDWallet.fromSeed(seed: testVector2);

  final testVector3 = hexStringToUint8List(
      '4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be');
  final vector3Wallet = HDWallet.fromSeed(seed: testVector3);

  final testVector4 = hexStringToUint8List(
      '3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678');
  final vector4Wallet = HDWallet.fromSeed(seed: testVector4);

  group('hdwallet', () {
    test('test vector 1 chain m', () {
      final childKey = vector1Wallet.deriveKeyByPath(path: 'm');
      final extPub = childKey.serializePublic(HDExtendedKeyVersion.xpub);
      expect(extPub,
          'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8');
      final extPriv = childKey.serializePrivate(HDExtendedKeyVersion.xprv);
      expect(extPriv,
          'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi');
    });

    test("test vector 1 chain m/0'", () {
      final childKey = vector1Wallet.deriveKeyByPath(path: "m/0'");
      final extPub = childKey.serializePublic(HDExtendedKeyVersion.xpub);
      expect(extPub,
          'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw');
      final extPriv = childKey.serializePrivate(HDExtendedKeyVersion.xprv);
      expect(extPriv,
          'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7');
    });

    test("test vector 1 chain m/0'/1", () {
      final childKey = vector1Wallet.deriveKeyByPath(path: "m/0'/1");
      final extPub = childKey.serializePublic(HDExtendedKeyVersion.xpub);
      expect(extPub,
          'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ');
      final extPriv = childKey.serializePrivate(HDExtendedKeyVersion.xprv);
      expect(extPriv,
          'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs');
    });

    test("test vector 1 chain m/0'/1/2'", () {
      final childKey = vector1Wallet.deriveKeyByPath(path: "m/0'/1/2'");
      final extPub = childKey.serializePublic(HDExtendedKeyVersion.xpub);
      expect(extPub,
          'xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5');
      final extPriv = childKey.serializePrivate(HDExtendedKeyVersion.xprv);
      expect(extPriv,
          'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM');
    });

    test("test vector 1 chain m/0'/1/2'/2", () {
      final childKey = vector1Wallet.deriveKeyByPath(path: "m/0'/1/2'/2");
      final extPub = childKey.serializePublic(HDExtendedKeyVersion.xpub);
      expect(extPub,
          'xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV');
      final extPriv = childKey.serializePrivate(HDExtendedKeyVersion.xprv);
      expect(extPriv,
          'xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334');
    });

    test("test vector 1 chain m/0'/1/2'/2/1000000000", () {
      final childKey =
          vector1Wallet.deriveKeyByPath(path: "m/0'/1/2'/2/1000000000");
      final extPub = childKey.serializePublic(HDExtendedKeyVersion.xpub);
      expect(extPub,
          'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy');
      final extPriv = childKey.serializePrivate(HDExtendedKeyVersion.xprv);
      expect(extPriv,
          'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76');
    });

    test('test vector 2 chain m', () {
      final childKey = vector2Wallet.deriveKeyByPath(path: 'm');
      final extPub = childKey.serializePublic(HDExtendedKeyVersion.xpub);
      expect(extPub,
          'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB');
      final extPriv = childKey.serializePrivate(HDExtendedKeyVersion.xprv);
      expect(extPriv,
          'xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U');
    });

    test("test vector 2 chain m/0", () {
      final childKey = vector2Wallet.deriveKeyByPath(path: "m/0");
      final extPub = childKey.serializePublic(HDExtendedKeyVersion.xpub);
      expect(extPub,
          'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH');
      final extPriv = childKey.serializePrivate(HDExtendedKeyVersion.xprv);
      expect(extPriv,
          'xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt');
    });

    test("test vector 2 chain m/0/2147483647'", () {
      final childKey = vector2Wallet.deriveKeyByPath(path: "m/0/2147483647'");
      final extPub = childKey.serializePublic(HDExtendedKeyVersion.xpub);
      expect(extPub,
          'xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a');
      final extPriv = childKey.serializePrivate(HDExtendedKeyVersion.xprv);
      expect(extPriv,
          'xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9');
    });

    test("test vector 2 chain m/0/2147483647'/1", () {
      final childKey = vector2Wallet.deriveKeyByPath(path: "m/0/2147483647'/1");
      final extPub = childKey.serializePublic(HDExtendedKeyVersion.xpub);
      expect(extPub,
          'xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon');
      final extPriv = childKey.serializePrivate(HDExtendedKeyVersion.xprv);
      expect(extPriv,
          'xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef');
    });

    test("test vector 2 chain m/0/2147483647'/1/2147483646'", () {
      final childKey =
          vector2Wallet.deriveKeyByPath(path: "m/0/2147483647'/1/2147483646'");
      final extPub = childKey.serializePublic(HDExtendedKeyVersion.xpub);
      expect(extPub,
          'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL');
      final extPriv = childKey.serializePrivate(HDExtendedKeyVersion.xprv);
      expect(extPriv,
          'xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc');
    });

    test("test vector 2 chain m/0/2147483647'/1/2147483646'/2", () {
      final childKey = vector2Wallet.deriveKeyByPath(
          path: "m/0/2147483647'/1/2147483646'/2");
      final extPub = childKey.serializePublic(HDExtendedKeyVersion.xpub);
      expect(extPub,
          'xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt');
      final extPriv = childKey.serializePrivate(HDExtendedKeyVersion.xprv);
      expect(extPriv,
          'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j');
    });

    test("test vector 3 chain m", () {
      final childKey = vector3Wallet.deriveKeyByPath(path: 'm');
      final extPub = childKey.serializePublic(HDExtendedKeyVersion.xpub);
      expect(extPub,
          'xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13');
      final extPriv = childKey.serializePrivate(HDExtendedKeyVersion.xprv);
      expect(extPriv,
          'xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6');
    });

    test("test vector 3 chain m/0'", () {
      final childKey = vector3Wallet.deriveKeyByPath(path: "m/0'");
      final extPub = childKey.serializePublic(HDExtendedKeyVersion.xpub);
      expect(extPub,
          'xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y');
      final extPriv = childKey.serializePrivate(HDExtendedKeyVersion.xprv);
      expect(extPriv,
          'xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L');
    });

    test("test vector 4 chain m", () {
      final childKey = vector4Wallet.deriveKeyByPath(path: "m");
      final extPub = childKey.serializePublic(HDExtendedKeyVersion.xpub);
      expect(extPub,
          'xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa');
      final extPriv = childKey.serializePrivate(HDExtendedKeyVersion.xprv);
      expect(extPriv,
          'xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv');
    });

    test("test vector 4 chain m/0'", () {
      final childKey = vector4Wallet.deriveKeyByPath(path: "m/0'");
      final extPub = childKey.serializePublic(HDExtendedKeyVersion.xpub);
      expect(extPub,
          'xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m');
      final extPriv = childKey.serializePrivate(HDExtendedKeyVersion.xprv);
      expect(extPriv,
          'xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G');
    });

    test("test vector 4 chain m/0'/1'", () {
      final childKey = vector4Wallet.deriveKeyByPath(path: "m/0'/1'");
      final extPub = childKey.serializePublic(HDExtendedKeyVersion.xpub);
      expect(extPub,
          'xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt');
      final extPriv = childKey.serializePrivate(HDExtendedKeyVersion.xprv);
      expect(extPriv,
          'xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1');
    });

    test("test vector 4 chain m/0'/1'", () {
      final childKey = vector4Wallet.deriveKeyByPath(path: "m/0'/1'");
      final extPub = childKey.serializePublic(HDExtendedKeyVersion.xpub);
      expect(extPub,
          'xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt');
      final extPriv = childKey.serializePrivate(HDExtendedKeyVersion.xprv);
      expect(extPriv,
          'xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1');
    });

    test("test invalid checksum", () {
      expect(
          () => HDExtendedKey(
              'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL'),
          throwsA(const TypeMatcher<InvalidChecksumException>()));
    });

    test('receiveAddress on mainnet', () {
      final hdPublicKey = hdWallet.getPublicKey(
          purpose: Purpose.BIP44, coinType: 0, account: 0, change: 0, index: 0);
      expect(hex.encode(hdPublicKey.publicKey),
          '03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e');
    });

    test('receiveAddress on testnet', () {
      final hdPublicKey = hdWallet.getPublicKey(
          purpose: Purpose.BIP44, coinType: 1, account: 0, change: 0, index: 0);
      expect(hex.encode(hdPublicKey.publicKey),
          '02a7451395735369f2ecdfc829c0f774e88ef1303dfe5b2f04dbaab30a535dfdd6');
    });

    test('changeAddress on mainnet', () {
      final hdPublicKey = hdWallet.getPublicKey(
          purpose: Purpose.BIP44, coinType: 0, account: 0, change: 1, index: 0);
      expect(hex.encode(hdPublicKey.publicKey),
          '03498b3ac8e882c5d693540c49adf22b7a1b99c1bb8047966739bfe8cdeb272e64');
    });

    test('changeAddress on testnet', () {
      final hdPublicKey = hdWallet.getPublicKey(
          purpose: Purpose.BIP44, coinType: 1, account: 0, change: 1, index: 0);
      expect(hex.encode(hdPublicKey.publicKey),
          '0320282ac6b3782721b1742c294530a9f250413361abbff659acc8352bc4c1f3f1');
    });

    test('hdwallet from account xpub', () {
      final hdExtendedKey = HDExtendedKey(
          'xpub6CudKadFxkN6jXWcJDJSWzt4tNt86ThhYEjtcTywfD5nsYcySEEhfGugKDLnv14ZDNnYBVbfYXbNvRp8cNNw9JAfoMTeph1BqGWYZA4DBDi');

      final hdWallet = HDWallet.fromKey(hdExtendedKey.key);
      final privateKey = hdWallet.deriveKeyByPath(path: "m/0/0");

      expect(
          address(privateKey.pubKeyHash), '1KaPvs5y3Fwyg4UvSc7pbvDTjk1BVWKgf9');

      expect(uint8ListToHexString(privateKey.pubKey),
          '036a62a11fdc05e2cd57b22dd8d0ad4a648bfb1dde857ce6062a5f8c29d7f02d08');
    });

    test('hdwallet from account xprv', () {
      final hdExtendedKey = HDExtendedKey(
          'xprv9yvGv56N8NooX3S9CBmS9rwLLM3dgzyrB1pHp5aL6sYozkHptgvT7UbCTuyXF1HUAaPiG24iDBbnp7EQr8eSJkANf9EodqUiATBXrtAAHjj');

      final hdWallet = HDWallet.fromKey(hdExtendedKey.key);
      final privateKey = hdWallet.deriveKeyByPath(path: "m/0/0");

      expect(
          address(privateKey.pubKeyHash), '1KaPvs5y3Fwyg4UvSc7pbvDTjk1BVWKgf9');

      expect(uint8ListToHexString(privateKey.pubKey),
          '036a62a11fdc05e2cd57b22dd8d0ad4a648bfb1dde857ce6062a5f8c29d7f02d08');

      expect(wifCompressed(privateKey.privKeyBytes!),
          'KwuBXScis8EHY926TzAkByRoTsNQGq5YB4kDwkdieK5oBWWSsUzE');
    });

    test('hdwallet from root xprv', () {
      final hdExtendedKey = HDExtendedKey(
          'yprvABrGsX5C9jantLFKTZNpFi2c6RKLw87EhgjRLMzdbwp5NjLsUR1oC2kte6k5YXy9hsCSSBVUtJL5XKwF1oFrofumWE3rFKRx6drdQQpkcR4');

      final hdWallet = HDWallet.fromKey(hdExtendedKey.key);
      final privateKey = hdWallet.deriveKey(
          purpose: hdExtendedKey.info.purpose,
          coinType: 0,
          account: 0,
          change: 0,
          index: 0);

      expect(uint8ListToHexString(privateKey.pubKey),
          '022d00ba4f264cd0d103ab4fe68cab0dbfbc7684476ef14feeb8d474408ab320cd');

      expect(wifCompressed(privateKey.privKeyBytes!),
          'L3F5WWjTcjPizhYwN9V5HDnHyTnNi5q7BFHWs8McTgdKBHptVAJD');
    });

    test('invalid extended key checksum', () {
      expect(
          () => HDExtendedKey(
              'xprv9yvGv56N8NooX3S9CBmS9rwLLM3dgzyrB1pHp5aL6sYozkHptgvT7UbCTuyXF1HUAaPiG24iDBbnp7EQr8eSJkANf9EodqUiATBXrtAAHjo'),
          throwsA(const TypeMatcher<InvalidChecksumException>()));
    });

    test('extended key serialization', () {
      expect(
          HDExtendedKey(
                  'xprv9yvGv56N8NooX3S9CBmS9rwLLM3dgzyrB1pHp5aL6sYozkHptgvT7UbCTuyXF1HUAaPiG24iDBbnp7EQr8eSJkANf9EodqUiATBXrtAAHjj')
              .serialize(),
          'xprv9yvGv56N8NooX3S9CBmS9rwLLM3dgzyrB1pHp5aL6sYozkHptgvT7UbCTuyXF1HUAaPiG24iDBbnp7EQr8eSJkANf9EodqUiATBXrtAAHjj');
    });

    test('extended key serialization2', () {
      expect(
          HDExtendedKey(
                  'xpub6CudKadFxkN6jXWcJDJSWzt4tNt86ThhYEjtcTywfD5nsYcySEEhfGugKDLnv14ZDNnYBVbfYXbNvRp8cNNw9JAfoMTeph1BqGWYZA4DBDi')
              .serialize(),
          'xpub6CudKadFxkN6jXWcJDJSWzt4tNt86ThhYEjtcTywfD5nsYcySEEhfGugKDLnv14ZDNnYBVbfYXbNvRp8cNNw9JAfoMTeph1BqGWYZA4DBDi');
    });

    test('extended key serialization3', () {
      expect(
          HDExtendedKey(
                  'yprvAJ5nxPMjEWX9Jas5pGu8RaAUjd3nPTLkHXhgDv5Bk7xHPv9rBjk4bdm9GJtskqpe7ZKVuQz6ZWAUjh61xH3xK7QbqTDuSe1iYeybk18HDgQ')
              .serialize(),
          'yprvAJ5nxPMjEWX9Jas5pGu8RaAUjd3nPTLkHXhgDv5Bk7xHPv9rBjk4bdm9GJtskqpe7ZKVuQz6ZWAUjh61xH3xK7QbqTDuSe1iYeybk18HDgQ');
    });

    test('extended key serialization4', () {
      expect(
          HDExtendedKey(
                  'yprvAJ5nxPMjEWX9Jas5pGu8RaAUjd3nPTLkHXhgDv5Bk7xHPv9rBjk4bdm9GJtskqpe7ZKVuQz6ZWAUjh61xH3xK7QbqTDuSe1iYeybk18HDgQ')
              .serializePublic(),
          'ypub6X59Mttd4t5SX4wYvJS8ni7DHetGnv4bekdH2JUoJTVGGiUzjH4K9S5d7a8bDMkqn7cY8zu5q9UDKKZMALo3w1wQ6NhwESGt5AvRZHRDMk6');
    });

    test('extended key serialization5', () {
      expect(
          () => HDExtendedKey(
                  'ypub6X59Mttd4t5SX4wYvJS8ni7DHetGnv4bekdH2JUoJTVGGiUzjH4K9S5d7a8bDMkqn7cY8zu5q9UDKKZMALo3w1wQ6NhwESGt5AvRZHRDMk6')
              .serializePrivate(),
          throwsA(const TypeMatcher<IllegalArgumentException>()));
    });

    test('hdwallet root extended privKey', () {
      final rootKey = hdWallet.deriveKeyByPath(path: 'm');
      expect(rootKey.serializePrivate(HDExtendedKeyVersion.xprv),
          'xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu');
    });

    test('hdwallet root extended pubKey', () {
      final rootKey = hdWallet.deriveKeyByPath(path: 'm');
      expect(rootKey.serializePublic(HDExtendedKeyVersion.xpub),
          'xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8');
    });

    test('hdwallet bip44 account 0 extended privKey', () {
      final bip44Key = hdWallet.deriveKeyByPath(path: "m/44'/0'/0'");
      expect(bip44Key.serializePrivate(HDExtendedKeyVersion.xprv),
          'xprv9xpXFhFpqdQK3TmytPBqXtGSwS3DLjojFhTGht8gwAAii8py5X6pxeBnQ6ehJiyJ6nDjWGJfZ95WxByFXVkDxHXrqu53WCRGypk2ttuqncb');
    });

    test('hdwallet bip44 account0 extended pubKey', () {
      final bip44Key = hdWallet.deriveKeyByPath(path: "m/44'/0'/0'");
      expect(bip44Key.serializePublic(HDExtendedKeyVersion.xpub),
          'xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj');
    });

    test('hdwallet bip44 address index 0', () {
      final address0Key = hdWallet.deriveKey(
          purpose: Purpose.BIP44, coinType: 0, account: 0, change: 0, index: 0);
      expect(
          base58checkCodec
              .encode(Base58CheckPayload(0, address0Key.pubKeyHash)),
          '1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA');
    });

    test('hdwallet bip44 address index 1', () {
      final address1Key = hdWallet.deriveKey(
          purpose: Purpose.BIP44, coinType: 0, account: 0, change: 0, index: 1);
      expect(
          base58checkCodec
              .encode(Base58CheckPayload(0, address1Key.pubKeyHash)),
          '1Ak8PffB2meyfYnbXZR9EGfLfFZVpzJvQP');
    });
  });
}
