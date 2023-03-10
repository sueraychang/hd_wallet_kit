// ignore_for_file: non_constant_identifier_names, implementation_imports

import 'dart:convert';
import 'dart:typed_data';

import 'package:hd_wallet_kit/src/eckey.dart';
import 'package:hd_wallet_kit/src/hdkey.dart';
import 'package:hd_wallet_kit/src/hdwalletkitexception.dart';
import 'package:hd_wallet_kit/utils.dart';
import 'package:pointycastle/export.dart';

import 'package:pointycastle/src/utils.dart' as utils;

/// From the BIP32 spec. Used when calculating the hmac of the seed
final Uint8List _masterKey = utf8.encoder.convert('Bitcoin seed');

class HDKeyDerivation {

  /// Generate a root key from the given seed.  The seed must be at least 128 bits.
  ///
  /// @param seed HD seed
  /// @return Root key
  /// @throws HDKeyDerivationException Generated master key is invalid
  static HDKey createRootKey(Uint8List seed) {
    if (seed.length < 16) {
      throw IllegalArgumentException('seed must be at least 128 bits');
    }

    final hash = hmacSha512(_masterKey, seed);
    final hashl = hash.sublist(0, 32);
    final hashr = hash.sublist(32, 64);

    BigInt privKey = utils.decodeBigIntWithSign(1, hashl);
    if (privKey.sign == 0) {
      throw const HDKeyDerivationException(
          'Generated master private key is zero');
    }
    if (privKey.compareTo(ECKey.ecParams.n) >= 0) {
      throw const HDKeyDerivationException(
          'Generated master private key is not less than N');
    }
    return HDKey.withPrivKey(privKey, hashr, null, 0, 0, 0, false);
  }

  /// Derive a child key from the specified parent.
  /// 
  /// The parent must have a private key in order to derive a private/public key pair.
  /// If the parent does not have a private key, only the public key can be derived.
  /// In addition, a hardened key cannot be derived from a public key since the algorithm requires
  /// the parent private key.
  /// 
  /// It is possible for key derivation to fail for a child number because the generated
  /// key is not valid.  If this happens, the application should generate a key using
  /// a different child number.
  ///
  /// @param parent      Parent key
  /// @param childNumber Child number
  /// @param hardened    TRUE to create a hardened key
  /// @return Derived key
  /// @throws HDKeyDerivationException Unable to derive key
  static HDKey deriveChildKey(HDKey parent, int childNumber, bool hardened) {
    if ((childNumber & HDKey.HARDENED_FLAG) != 0) {
      throw IllegalArgumentException(
          'Hardened flag must not be set in child number');
    }
    if (parent.privKey == null) {
      if (hardened) {
        throw IllegalArgumentException(
            'Hardened key requires parent private key');
      }
      return _derivePublicKey(parent, childNumber);
    } else {
      return _derivePrivateKey(parent, childNumber, hardened);
    }
  }

  /// Derive a child key from a private key
  ///
  /// @param parent      Parent key
  /// @param childNumber Child number
  /// @param hardened    TRUE to create a hardened key
  /// @return Derived key
  /// @throws HDKeyDerivationException Unable to derive key
  static HDKey _derivePrivateKey(HDKey parent, int childNumber, bool hardened) {
    Uint8List parentPubKey = parent.pubKey;
    if (parentPubKey.length != 33) {
      throw IllegalArgumentException('Parent public key is not 33 bytes');
    }
    var dataBuffer = Uint8List(37);
    if (hardened) {
      dataBuffer.setAll(0, parent.getPaddedPrivKeyBytes());
      dataBuffer.setAll(33, intToUint8List(childNumber | HDKey.HARDENED_FLAG));
    } else {
      dataBuffer.setAll(0, parentPubKey);
      dataBuffer.setAll(33, intToUint8List(childNumber));
    }

    final i = hmacSha512(parent.chainCode, dataBuffer);
    final il = i.sublist(0, 32);
    final ir = i.sublist(32, 64);
    BigInt ilInt = utils.decodeBigIntWithSign(1, il);
    if (ilInt.compareTo(ECKey.ecParams.n) >= 0) {
      throw const HDKeyDerivationException(
          'Derived private key is not less than N');
    }
    BigInt ki = (parent.privKey! + ilInt) % ECKey.ecParams.n;
    if (ki.sign == 0) {
      throw const HDKeyDerivationException('Derived private key is zero');
    }
    return HDKey.withPrivKey(
      ki,
      ir,
      parent,
      parent.getFingerprint(),
      parent.depth + 1,
      childNumber,
      hardened,
    );
  }

  /// Derive a child key from a public key
  ///
  /// @param parent      Parent key
  /// @param childNumber Child number
  /// @return Derived key
  /// @throws HDKeyDerivationException Unable to derive key
  static HDKey _derivePublicKey(HDKey parent, int childNumber) {
    var dataBuffer = Uint8List(37);
    dataBuffer.setAll(0, parent.pubKey);
    dataBuffer.setAll(33, intToUint8List(childNumber));

    final i = hmacSha512(parent.chainCode, dataBuffer);
    final il = i.sublist(0, 32);
    final ir = i.sublist(32, 64);
    BigInt ilInt = utils.decodeBigIntWithSign(1, il);
    if (ilInt.compareTo(ECKey.ecParams.n) >= 0) {
      throw const HDKeyDerivationException(
          'Derived private key is not less than N');
    }
    ECPoint? pubKeyPoint = ECKey.ecParams.curve.decodePoint(parent.pubKey);
    ECPoint? Ki = ECKey.pubKeyPointFromPrivKey(ilInt)! + pubKeyPoint!;
    if (Ki == ECKey.ecParams.curve.infinity) {
      throw const HDKeyDerivationException(
          'Derived public key equals infinity');
    }
    return HDKey.withPubKey(
      Ki!.getEncoded(true),
      ir,
      parent,
      parent.getFingerprint(),
      parent.depth + 1,
      childNumber,
      false,
    );
  }
}
