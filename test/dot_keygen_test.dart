import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:urbit_ob/urbit_ob.dart' as ob;

import 'package:dot_keygen/dot_keygen.dart' as keygen;
import 'package:web3dart/credentials.dart';
import 'package:web3dart/crypto.dart';

final kTicket = "~sampel-ticlet-migfun-falmel";
final kSecret = utf8.encode(kTicket);

/// helper to derive path using constant secret
Uint8List _derive(List<String> path) => keygen.derive(kSecret, path);

void main() {
  group('.derive', () {
    test('should derive root secret', () {
      final secret = _derive([keygen.ROOT]);
      expect(secret, hasLength(keygen.SECRET_LENGTH));
    });

    test('should derive identity secret', () {
      final secret = _derive([keygen.ROOT, 'matt']);
      expect(secret, hasLength(keygen.SECRET_LENGTH));
    });

    test('should derive different secrets for different subpaths', () {
      final ethereumSecret = _derive([
        keygen.ROOT,
        'matt',
        keygen.Domain.Ethereum,
      ]);

      final bitcoinSecret = _derive([keygen.ROOT, 'matt', keygen.Domain.Bitcoin]);

      expect(ethereumSecret, hasLength(keygen.SECRET_LENGTH));
      expect(bitcoinSecret, hasLength(keygen.SECRET_LENGTH));
      expect(ethereumSecret, isNot(equals(bitcoinSecret)));
    });

    group('subpath tickets', () {
      final dotSecret = _derive([keygen.ROOT, 'matt']);
      final bitcoinSecret = _derive([keygen.ROOT, 'matt', keygen.Domain.Bitcoin]);
      final dotTicket = ob.patq(dotSecret);

      test("ticket should encode identity secret", () {
        expect(dotSecret, equals(ob.patq2buf(dotTicket)));
      });

      test("secret can derive from within the graph", () {
        final newBitcoinSecret = keygen.derive(dotSecret, [keygen.Domain.Bitcoin]);
        expect(bitcoinSecret, equals(newBitcoinSecret));
      });

      test("identity ticket should be able to derive known path", () {
        final sameBitcoinSecret = keygen.derive(ob.patq2buf(dotTicket), [keygen.Domain.Bitcoin]);
        expect(bitcoinSecret, equals(sameBitcoinSecret));
      });
    });
  });

  group("bitcoin", () {
    final secret = _derive([keygen.ROOT, 'matt', keygen.Domain.Bitcoin]);
    final wallet = keygen.toBitcoinWallet(secret);

    test("generates a valid address", () {
      // https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
      expect(wallet.address.length, greaterThanOrEqualTo(26));
      expect(wallet.address.length, lessThanOrEqualTo(34));
    });

    test("generates a valid private key", () {
      // https://en.bitcoin.it/wiki/Private_key
      expect(wallet.privKey, hasLength(64));
    });

    test('signs and verifies data', () {
      final data = 'hello world';
      final signature = wallet.sign(data);

      expect(wallet.verify(message: data, signature: signature), isTrue);
    });
  });

  group("ethereum", () {
    final secret = _derive([keygen.ROOT, 'matt', keygen.Domain.Ethereum]);
    final wallet = keygen.toEthereumWallet(secret);

    test("generates a valid address", () {
      final address =
          EthereumAddress.fromPublicKey(privateKeyBytesToPublic(wallet.privateKey.privateKey));
      expect(address.hex, startsWith('0x'));
      expect(address.hexNo0x, hasLength(40));
    });

    test("signs and verifies data", () async {
      final data = utf8.encode('hello world');
      final signature = await wallet.privateKey.sign(data);

      expect(signature, hasLength(65)); // r (32) + s (32) + v (1)
    });
  });

  group("different identities", () {
    test("should have different domain secrets", () {
      final a = keygen.derive(kSecret, [keygen.ROOT, 'matt', keygen.Domain.Bitcoin]);
      final b = keygen.derive(kSecret, [keygen.ROOT, 'shrugs', keygen.Domain.Bitcoin]);
      expect(a, isNot(equals(b)));
    });
  });
}
