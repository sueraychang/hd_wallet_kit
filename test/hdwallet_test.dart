import 'dart:typed_data';

import 'package:base58check/base58check.dart';
import 'package:convert/convert.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hd_wallet_kit/src/hdextendedkey.dart';
import 'package:hd_wallet_kit/src/hdwallet.dart';
import 'package:hd_wallet_kit/src/hdwalletkitexception.dart';
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

  final seed = hexStringToUint8List(
      '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4');
  final hdWalletMainNet = HDWallet.fromSeed(seed, 0, Purpose.BIP44);
  final hdWalletTestNet = HDWallet.fromSeed(seed, 1, Purpose.BIP44);

  group('hdwallet', () {
    test('receiveAddress on mainnet', () {
      final hdPublicKey = hdWalletMainNet.getPublicKey(0, 0, 0);
      expect(hex.encode(hdPublicKey.publicKey),
          '03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e');
    });

    test('receiveAddress on testnet', () {
      final hdPublicKey = hdWalletTestNet.getPublicKey(0, 0, 0);
      expect(hex.encode(hdPublicKey.publicKey),
          '02a7451395735369f2ecdfc829c0f774e88ef1303dfe5b2f04dbaab30a535dfdd6');
    });

    test('changeAddress on mainnet', () {
      final hdPublicKey = hdWalletMainNet.getPublicKey(0, 1, 0);
      expect(hex.encode(hdPublicKey.publicKey),
          '03498b3ac8e882c5d693540c49adf22b7a1b99c1bb8047966739bfe8cdeb272e64');
    });

    test('changeAddress on testnet', () {
      final hdPublicKey = hdWalletTestNet.getPublicKey(0, 1, 0);
      expect(hex.encode(hdPublicKey.publicKey),
          '0320282ac6b3782721b1742c294530a9f250413361abbff659acc8352bc4c1f3f1');
    });

    test('hdwallet from account xpub', () {
      final hdExtendedKey = HDExtendedKey(
          'xpub6CudKadFxkN6jXWcJDJSWzt4tNt86ThhYEjtcTywfD5nsYcySEEhfGugKDLnv14ZDNnYBVbfYXbNvRp8cNNw9JAfoMTeph1BqGWYZA4DBDi');

      final hdWallet =
          HDWallet.fromKey(hdExtendedKey.key, 0, hdExtendedKey.info.purpose);
      final privateKey = hdWallet.getPrivateKeyByPath("m/0/0");

      expect(
          address(privateKey.pubKeyHash), '1KaPvs5y3Fwyg4UvSc7pbvDTjk1BVWKgf9');

      expect(uint8ListToHexString(privateKey.pubKey),
          '036a62a11fdc05e2cd57b22dd8d0ad4a648bfb1dde857ce6062a5f8c29d7f02d08');
    });

    test('hdwallet from account xprv', () {
      final hdExtendedKey = HDExtendedKey(
          'xprv9yvGv56N8NooX3S9CBmS9rwLLM3dgzyrB1pHp5aL6sYozkHptgvT7UbCTuyXF1HUAaPiG24iDBbnp7EQr8eSJkANf9EodqUiATBXrtAAHjj');

      final hdWallet =
          HDWallet.fromKey(hdExtendedKey.key, 0, hdExtendedKey.info.purpose);
      final privateKey = hdWallet.getPrivateKeyByPath("m/0/0");

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

      final hdWallet =
          HDWallet.fromKey(hdExtendedKey.key, 0, hdExtendedKey.info.purpose);
      final privateKey = hdWallet.getPrivateKey(0, 0, 0);

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
  });
}
