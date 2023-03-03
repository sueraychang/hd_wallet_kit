import 'dart:typed_data';

import 'package:hd_wallet_kit/src/base58.dart';
import 'package:hd_wallet_kit/src/hdextendedkeyversion.dart';
import 'package:hd_wallet_kit/src/hdkey.dart';
import 'package:hd_wallet_kit/src/hdkeyderivation.dart';
import 'package:hd_wallet_kit/src/hdwallet.dart';
import 'package:hd_wallet_kit/src/hdwalletkitexception.dart';
import 'package:hd_wallet_kit/utils.dart';

// ignore: implementation_imports
import 'package:pointycastle/src/utils.dart' as utils;

enum DerivedType {
  bip32,
  master,
  account;

  static DerivedType initFrom(int depth) {
    switch (depth) {
      case 0:
        return DerivedType.master;
      case 3:
        return DerivedType.account;
      default:
        return DerivedType.bip32;
    }
  }
}

class HDExtendedKey {
  late final HDKey key;
  late final HDExtendedKeyVersion _version;

  DerivedType get derivedType => DerivedType.initFrom(key.depth);

  KeyInfo get info => KeyInfo(
        _version.purpose,
        _version.extendedKeyCoinType,
        derivedType,
        _version.isPublic,
      );

  /// Return extended key by serialized key
  ///
  /// @return HDExtendedKey
  HDExtendedKey(String serialized) {
    key = _keyFromSerialized(serialized);
    _version = _versionFromSerialized(serialized);
  }

  /// Return extended key by seed & purpose
  ///
  /// @param seed        Seed
  /// @param purpose     Wallet purpose
  /// @return HDExtendedKey
  HDExtendedKey.fromSeed(Uint8List seed, Purpose purpose) {
    key = HDKeyDerivation.createRootKey(seed);
    switch (purpose) {
      case Purpose.BIP44:
        _version = HDExtendedKeyVersion.xprv;
        break;
      case Purpose.BIP49:
        _version = HDExtendedKeyVersion.yprv;
        break;
      case Purpose.BIP84:
        _version = HDExtendedKeyVersion.zprv;
        break;
    }
  }

  /// Serialize the extended public key.
  String serializePublic() => key.serializePublic(_version.pubKey);

  /// Serialize the extended private key.
  String serializePrivate() => key.serializePrivate(_version.privKey);

  /// Serialize the extended key.
  String serialize() => key.hasPrivKey ? serializePrivate() : serializePublic();

  static const int _length = 82;

  static HDKey _keyFromSerialized(String serialized) {
    final version = _versionFromSerialized(serialized);

    final data = Uint8List.fromList(base58codec.decode(serialized));
    if (data.length != _length) {
      throw WrongKeyLengthException('wrong key length ${data.length}');
    }

    final depth = data[4] & 0xff;
    int parentFingerprint = data[5] & 0x000000ff;
    parentFingerprint = parentFingerprint << 8;
    parentFingerprint = parentFingerprint | (data[6] & 0x000000ff);
    parentFingerprint = parentFingerprint << 8;
    parentFingerprint = parentFingerprint | (data[7] & 0x000000ff);
    parentFingerprint = parentFingerprint << 8;
    parentFingerprint = parentFingerprint | (data[8] & 0x000000ff);

    int sequence = data[9] & 0x000000ff;
    sequence = sequence << 8;
    sequence = sequence | (data[10] & 0x000000ff);
    sequence = sequence << 8;
    sequence = sequence | (data[11] & 0x000000ff);
    sequence = sequence << 8;
    sequence = sequence | (data[12] & 0x000000ff);

    final hardened = sequence & HDKey.HARDENED_FLAG != 0;
    final childNumber = sequence & 0x7fffffff;

    final derivedType = DerivedType.initFrom(depth);
    if (derivedType == DerivedType.bip32) {
      throw const WrongDerivedTypeException('wrong derived type');
    }

    validateChecksum(data);

    final bytes = data.sublist(0, data.length - 4);
    final chainCode = bytes.sublist(13, 13 + 32);
    final pubOrPriv = bytes.sublist(13 + 32, bytes.length);

    return !version.isPublic
        ? HDKey.withPrivKey(
            utils.decodeBigIntWithSign(1, pubOrPriv),
            chainCode,
            null,
            parentFingerprint,
            depth,
            childNumber,
            hardened,
          )
        : HDKey.withPubKey(
            pubOrPriv,
            chainCode,
            null,
            parentFingerprint,
            depth,
            childNumber,
            hardened,
          );
  }

  static HDExtendedKeyVersion _versionFromSerialized(String serialized) {
    final prefix = serialized.substring(0, 4);
    final result = HDExtendedKeyVersion.initFrom(prefix);
    if (result == null) {
      throw WrongVersionException('wrong version: $prefix');
    }
    return result;
  }

  static validateChecksum(Uint8List extendedKey) {
    final bytes = extendedKey.sublist(0, extendedKey.length - 4);
    final checksum =
        extendedKey.sublist(extendedKey.length - 4, extendedKey.length);
    final hash = doubleSHA256Digest(bytes).getRange(0, 4);
    final checksumString =
        checksum.map((e) => e.toRadixString(16).padLeft(2, '0')).join();
    final hashString =
        hash.map((e) => e.toRadixString(16).padLeft(2, '0')).join();
    if (checksumString != hashString) {
      throw const InvalidChecksumException('invalid checksum');
    }
  }
}

class KeyInfo {
  final Purpose purpose;
  final ExtendedKeyCoinType coinType;
  final DerivedType derivedType;
  final bool isPublic;

  KeyInfo(this.purpose, this.coinType, this.derivedType, this.isPublic);
}
