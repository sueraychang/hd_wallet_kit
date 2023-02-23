class HDWalletKitException implements Exception {
  final String message;

  const HDWalletKitException(this.message);

  @override
  String toString() {
    return "HDWalletKitException: $message";
  }
}

class IllegalArgumentException extends HDWalletKitException {
  IllegalArgumentException(String message) : super(message);
}

// Mnemonic Exceptions
class EmptyEntropyException extends HDWalletKitException {
  EmptyEntropyException({required String message})
      : super('MnemonicException: $message');
}

class InvalidMnemonicCountException extends HDWalletKitException {
  InvalidMnemonicCountException({required String message})
      : super('MnemonicException: $message');
}

class InvalidMnemonicKeyException extends HDWalletKitException {
  InvalidMnemonicKeyException({required String message})
      : super('MnemonicException: $message');
}

class ChecksumException extends HDWalletKitException {
  ChecksumException({required String message})
      : super('MnemonicException: $message');
}

// HDKeyDerivation
class HDKeyDerivationException extends HDWalletKitException {
  const HDKeyDerivationException(String message)
      : super('HDKeyDerivation: $message');
}

// HDExtendedKey
class WrongVersionException extends HDWalletKitException {
  const WrongVersionException(String message)
      : super('HDExtendedKeyException: $message');
}

class WrongKeyLengthException extends HDWalletKitException {
  const WrongKeyLengthException(String message)
      : super('HDExtendedKeyException: $message');
}

class WrongDerivedTypeException extends HDWalletKitException {
  const WrongDerivedTypeException(String message)
      : super('HDExtendedKeyException: $message');
}

class InvalidChecksumException extends HDWalletKitException {
  const InvalidChecksumException(String message)
      : super('HDExtendedKeyException: $message');
}
