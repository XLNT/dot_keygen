# dot_keygen

arbitrary hierarchical keygen in Dart.

## How it Works

A root `ticket` is used as secret input into the key derivation function (scrypt, until argon2id is available in Dart) and then secrets are recursively derived according to a path through the graph.

Canonically, the first derivation indicates an identity and further derivations represent wallets. Wallets can be well-known and have domain-specific representations using the derived secret. For example, a secret can be generated and used as input to a bitcoin wallet like so:

```dart
import 'dart:convert';
import 'package:dot_keygen/dot_keygen.dart' as keygen;

final myTicket = "~sampel-ticlet-migfun-falmel"; // or any string, really ¯\_(ツ)_/¯

final secret = keygen.derive(
  utf8.encode(myTicket),
  [keygen.ROOT, 'matt', keygen.Domain.Bitcoin],
);

final wallet = keygen.toBitcoinWallet(secret);

// https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
expect(wallet.address.length, greaterThanOrEqualTo(26));
expect(wallet.address.length, lessThanOrEqualTo(34));
```

and an Ethereum wallet like

```dart
final secret = keygen.derive(
  utf8.encode(myTicket),
  [keygen.ROOT, 'matt', keygen.Domain.Ethereum],
);

final wallet = keygen.toEthereumWallet(secret);

final address = EthereumAddress.fromPublicKey(
    privateKeyBytesToPublic(wallet.privateKey.privateKey)
  );

expect(address.hex, startsWith('0x'));
expect(address.hexNo0x, hasLength(40));
```

identity subpaths can be package identifiers (i.e. `org.ethereum`) or similar, perhaps backed by an on-chain registry / naming system (ENS, HNS, whatever). Perhaps one subpath should be `apps` or `well-known` that nests these well-known package IDs. idk, it's pretty arbitrary and up in the air.

## Concerns

1. I'm not a security person and I have no business writing these libraries.
2. We use a constant secret length of 8 bytes at every path, which makes the tickets a nice 4-chunk length but only gives them 64 bits of entropy, making them not particularly good for security. In the future we should allow arbitrary secret length at each path to avoid situations where, for example, the bitcoin secret must have at least 128 bits so we just SHA256 the 64 bit secret instead of actually generating a 128 bit secret (lol).
3. We probably want a secure random number generator in here somewhere (iirc, I wrote one in an old project...)
4. Because of the recursive nature of derivation, deriving a large path takes linearly long time and cannot be done in parallel. Problem is avoided when not starting from the root (i.e. using an identity secret to derive a wallet is 1x cost instead of 2x if deriving from root).
