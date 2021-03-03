#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstack wallet recovery tool by NotATether
    ~~~~~

    copyright: (c) 2021 by Ali Sherief

This file uses parts of Registrar and its dependencies.

    Registrar is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Registrar is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Registrar. If not, see <http://www.gnu.org/licenses/>.

For legal information about the dependencies of Registrar, see their
respective copyright notices.
"""

import ecdsa
import hashlib
from hashlib import sha256, sha512
from utilitybelt import change_charset
from Crypto.Cipher import AES
from bitcoin import compress, encode_privkey, get_privkey_format
from binascii import hexlify, unhexlify
from ecdsa.keys import SigningKey, VerifyingKey
import getpass

from ecdsa.ellipticcurve import INFINITY
from cachetools.func import lru_cache
import re
import base58
from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point as _ECDSA_Point
from ecdsa.numbertheory import square_root_mod_prime
import json
import sys
import os.path
import os
import base64
import time
import hmac
from os import urandom
import six

if six.PY3:
    long = int

def ensure_bytes(data):
    if not isinstance(data, six.binary_type):
        return data.encode('utf-8')
    return data


def ensure_str(data):
    if isinstance(data, six.binary_type):
        return data.decode('utf-8')
    elif not isinstance(data, six.string_types):
        raise ValueError("Invalid value for string")
    return data

def chr_py2(num):
    """Ensures that python3's chr behavior matches python2."""
    if six.PY3:
        return bytes([num])
    return chr(num)


def hash160(data):
    """Return ripemd160(sha256(data))"""
    rh = hashlib.new('ripemd160', sha256(data).digest())
    return rh.digest()


def is_hex_string(string):
    """Check if the string is only composed of hex characters."""
    pattern = re.compile(r'[A-Fa-f0-9]+')
    if isinstance(string, six.binary_type):
        string = str(string)
    return pattern.match(string) is not None


def long_to_hex(l, size):
    """Encode a long value as a hex string, 0-padding to size.

    Note that size is the size of the resulting hex string. So, for a 32Byte
    long size should be 64 (two hex characters per byte"."""
    f_str = "{0:0%sx}" % size
    return ensure_bytes(f_str.format(l).lower())


def long_or_int(val, *args):
    return long(val, *args)

class BitcoinMainNet(object):
    """Bitcoin MainNet version bytes.

    From https://github.com/bitcoin/bitcoin/blob/v0.9.0rc1/src/chainparams.cpp
    """
    NAME = "Bitcoin Main Net"
    SCRIPT_ADDRESS = 0x05  # int(0x05) = 5
    PUBKEY_ADDRESS = 0x00  # int(0x00) = 0  # Used to create payment addresses
    SECRET_KEY = 0x80      # int(0x80) = 128  # Used for WIF format
    EXT_PUBLIC_KEY = 0x0488B21E  # Used to serialize public BIP32 addresses
    EXT_SECRET_KEY = 0x0488ADE4  # Used to serialize private BIP32 addresses
    # this wallet has EXT_SECRET_KEY = 0x4c382c2

class Key(object):
    def __init__(self, network, compressed=False):
        """Construct a Key."""
        # Set network first because set_key needs it
        self.network = network
        self.compressed = compressed

    def __eq__(self, other):
        return (other and
                self.network == other.network and
                type(self) == type(other))

    def __ne__(self, other):
        return not self == other

    __hash__ = object.__hash__

    def get_key(self):
        raise NotImplementedError()


class PrivateKey(Key):
    def __init__(self, secret_exponent, network=BitcoinMainNet,
                 *args, **kwargs):
        if not isinstance(secret_exponent, six.integer_types):
            raise ValueError("secret_exponent must be a long")
        super(PrivateKey, self).__init__(network=network, *args, **kwargs)
        self._private_key = SigningKey.from_secret_exponent(
            secret_exponent, curve=SECP256k1)

    def get_key(self):
        """Get the key - a hex formatted private exponent for the curve."""
        return ensure_bytes(hexlify(self._private_key.to_string()))

    def get_public_key(self):
        """Get the PublicKey for this PrivateKey."""
        return PublicKey.from_verifying_key(
            self._private_key.get_verifying_key(),
            network=self.network, compressed=self.compressed)

    def get_extended_key(self):
        """Get the extended key.

        Extended keys contain the network bytes and the public or private
        key.
        """
        network_hex_chars = hexlify(
            chr_py2(self.network.SECRET_KEY))
        return ensure_bytes(network_hex_chars + self.get_key())

    def export_to_wif(self, compressed=None):
        """Export a key to WIF.

        :param compressed: False if you want a standard WIF export (the most
            standard option). True if you want the compressed form (Note that
            not all clients will accept this form). Defaults to None, which
            in turn uses the self.compressed attribute.
        :type compressed: bool
        See https://en.bitcoin.it/wiki/Wallet_import_format for a full
        description.
        """
        # Add the network byte, creating the "extended key"
        extended_key_hex = self.get_extended_key()
        extended_key_bytes = unhexlify(ensure_bytes(extended_key_hex))
        if compressed is None:
            compressed = self.compressed
        if compressed:
            extended_key_bytes += b'\01'
        # And return the base58-encoded result with a checksum
        return ensure_str(base58.b58encode_check(extended_key_bytes))

    def _public_child(child_number):
        raise NotImplementedError()

class PublicKey(Key):
    def __init__(self, verifying_key, network=BitcoinMainNet, *args, **kwargs):
        """Create a public key.

        :param verifying_key: The ECDSA VerifyingKey corresponding to this
            public key.
        :type verifying_key: ecdsa.VerifyingKey
        :param network: The network you want (Networks just define certain
            constants, like byte-prefixes on public addresses).
        :type network: See `bitmerchant.wallet.network`
        """
        super(PublicKey, self).__init__(network=network, *args, **kwargs)
        self._verifying_key = verifying_key
        self.x = verifying_key.pubkey.point.x()
        self.y = verifying_key.pubkey.point.y()

    def to_point(self):
        return self._verifying_key.pubkey.point

    @classmethod
    def from_point(cls, point, network=BitcoinMainNet, **kwargs):
        """Create a PublicKey from a point on the SECP256k1 curve.

        :param point: A point on the SECP256k1 curve.
        :type point: SECP256k1.point
        """
        verifying_key = VerifyingKey.from_public_point(point, curve=SECP256k1)
        return cls.from_verifying_key(verifying_key, network=network, **kwargs)

    def create_point(self, x, y):
        """Create an ECDSA point on the SECP256k1 curve with the given coords.

        :param x: The x coordinate on the curve
        :type x: long
        :param y: The y coodinate on the curve
        :type y: long
        """
        if (not isinstance(x, six.integer_types) or
                not isinstance(y, six.integer_types)):
            raise ValueError("The coordinates must be longs.")
        return _ECDSA_Point(SECP256k1.curve, x, y)

    def get_key(self, compressed=None):
        """Get the hex-encoded key.

        :param compressed: False if you want a standard 65 Byte key (the most
            standard option). True if you want the compressed 33 Byte form.
            Defaults to None, which in turn uses the self.compressed attribute.
        :type compressed: bool

        PublicKeys consist of an ID byte, the x, and the y coordinates
        on the elliptic curve.

        In the case of uncompressed keys, the ID byte is 04.
        Compressed keys use the SEC1 format:
            If Y is odd: id_byte = 03
            else: id_byte = 02

        Note that I pieced this algorithm together from the pycoin source.

        This is documented in http://www.secg.org/collateral/sec1_final.pdf
        but, honestly, it's pretty confusing.

        I guess this is a pretty big warning that I'm not *positive* this
        will do the right thing in all cases. The tests pass, and this does
        exactly what pycoin does, but I'm not positive pycoin works either!
        """
        if compressed is None:
            compressed = self.compressed
        if compressed:
            parity = 2 + (self.y & 1)  # 0x02 even, 0x03 odd
            return ensure_bytes(
                long_to_hex(parity, 2) +
                long_to_hex(self.x, 64))
        else:
            return ensure_bytes(
                b'04' +
                long_to_hex(self.x, 64) +
                long_to_hex(self.y, 64))

    @classmethod
    def from_hex_key(cls, key, network=BitcoinMainNet):
        """Load the PublicKey from a compressed or uncompressed hex key.

        This format is defined in PublicKey.get_key()
        """
        if len(key) == 130 or len(key) == 66:
            # It might be a hexlified byte array
            try:
                key = unhexlify(ensure_bytes(key))
            except (TypeError, binascii.Error):
                pass
        key = ensure_bytes(key)

        compressed = False
        id_byte = key[0]
        if not isinstance(id_byte, six.integer_types):
            id_byte = ord(id_byte)
        if id_byte == 4:
            # Uncompressed public point
            # 1B ID + 32B x coord + 32B y coord = 65 B
            if len(key) != 65:
                raise KeyParseError("Invalid key length")
            public_pair = PublicPair(
                long_or_int(hexlify(key[1:33]), 16),
                long_or_int(hexlify(key[33:]), 16))
        elif id_byte in [2, 3]:
            # Compressed public point!
            compressed = True
            if len(key) != 33:
                raise KeyParseError("Invalid key length")
            y_odd = bool(id_byte & 0x01)  # 0 even, 1 odd
            x = long_or_int(hexlify(key[1:]), 16)
            # The following x-to-pair algorithm was lifted from pycoin
            # I still need to sit down an understand it. It is also described
            # in http://www.secg.org/collateral/sec1_final.pdf
            curve = SECP256k1.curve
            p = curve.p()
            # For SECP256k1, curve.a() is 0 and curve.b() is 7, so this is
            # effectively (x ** 3 + 7) % p, but the full equation is kept
            # for just-in-case-the-curve-is-broken future-proofing
            alpha = (pow(x, 3, p) + curve.a() * x + curve.b()) % p
            beta = square_root_mod_prime(alpha, p)
            y_even = not y_odd
            if y_even == bool(beta & 1):
                public_pair = PublicPair(x, p - beta)
            else:
                public_pair = PublicPair(x, beta)
        else:
            raise KeyParseError("The given key is not in a known format.")
        return cls.from_public_pair(public_pair, network=network,
                                    compressed=compressed)
    @classmethod
    def from_public_pair(cls, pair, network=BitcoinMainNet, **kwargs):
        point = _ECDSA_Point(SECP256k1.curve, pair.x, pair.y)
        return cls.from_point(point, network=network, **kwargs)

    @classmethod
    def from_verifying_key(
            cls, verifying_key, network=BitcoinMainNet, **kwargs):
        return cls(verifying_key, network=network, **kwargs)

class Wallet(object):
    """A BIP32 wallet is made up of Wallet nodes.

    A Private node contains both a public and private key, while a public
    node contains only a public key.

    **WARNING**:

    When creating a NEW wallet you MUST back up the private key. If
    you don't then any coins sent to your address will be LOST FOREVER.

    You need to save the private key somewhere. It is OK to just write
    it down on a piece of paper! Don't share this key with anyone!

    >>> my_wallet = Wallet.from_master_secret(
    ...     key='correct horse battery staple')
    >>> private = my_wallet.serialize(private=True)
    >>> private  # doctest: +ELLIPSIS
    u'xprv9s21ZrQH143K2mDJW8vDeFwbyDbFv868mM2Zr87rJSTj8q16Unkaq1pryiV...'

    If you want to use this wallet on your website to accept bitcoin or
    altcoin payments, you should first create a primary child.

    BIP32 Hierarchical Deterministic Wallets are described in this BIP:
    https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
    """
    def __init__(self,
                 chain_code,
                 depth=0,
                 parent_fingerprint=0,
                 child_number=0,
                 private_exponent=None,
                 private_key=None,
                 public_pair=None,
                 public_key=None,
                 network=BitcoinMainNet):

        """Construct a new BIP32 compliant wallet.

        You probably don't want to use this init methd. Instead use one
        of the 'from_master_secret' or 'deserialize' cosntructors.
        """
        if (not (private_exponent or private_key) and
                not (public_pair or public_key)):
            raise InsufficientKeyDataError(
                "You must supply one of private_exponent or public_pair")

        self.private_key = None
        self.public_key = None
        if private_key:
            if not isinstance(private_key, PrivateKey):
                raise InvalidPrivateKeyError(
                    "private_key must be of type "
                    "bitmerchant.wallet.keys.PrivateKey")
            self.private_key = private_key
        elif private_exponent:
            self.private_key = PrivateKey(
                private_exponent, network=network)

        if public_key:
            if not isinstance(public_key, PublicKey):
                raise InvalidPublicKeyError(
                    "public_key must be of type "
                    "bitmerchant.wallet.keys.PublicKey")
            self.public_key = public_key
        elif public_pair:
            self.public_key = PublicKey.from_public_pair(
                public_pair, network=network)
        else:
            self.public_key = self.private_key.get_public_key()

        if (self.private_key and self.private_key.get_public_key() !=
                self.public_key):
            raise KeyMismatchError(
                "Provided private and public values do not match")

        def h(val, hex_len):
            if isinstance(val, six.integer_types):
                return long_to_hex(val, hex_len)
            elif (isinstance(val, six.string_types) or
                    isinstance(val, six.binary_type)) and is_hex_string(val):
                val = ensure_bytes(val)
                if len(val) != hex_len:
                    raise ValueError("Invalid parameter length")
                return val
            else:
                raise ValueError("Invalid parameter type")

        def l(val):
            if isinstance(val, six.integer_types):
                return long_or_int(val)
            elif (isinstance(val, six.string_types) or
                    isinstance(val, six.binary_type)):
                val = ensure_bytes(val)
                if not is_hex_string(val):
                    val = hexlify(val)
                return long_or_int(val, 16)
            else:
                raise ValueError("parameter must be an int or long")

        self.network = network
        self.depth = l(depth)
        if (isinstance(parent_fingerprint, six.string_types) or
                isinstance(parent_fingerprint, six.binary_type)):
            val = ensure_bytes(parent_fingerprint)
            if val.startswith(b"0x"):
                parent_fingerprint = val[2:]
        self.parent_fingerprint = b"0x" + h(parent_fingerprint, 8)
        self.child_number = l(child_number)
        self.chain_code = h(chain_code, 64)

    @property
    def fingerprint(self):
        """The first 32 bits of the identifier are called the fingerprint."""
        # 32 bits == 4 Bytes == 8 hex characters
        return b'0x' + self.identifier[:8]

    @classmethod
    def deserialize(cls, key, network=BitcoinMainNet):
        """Load the ExtendedBip32Key from a hex key.

        The key consists of

            * 4 byte version bytes (network key)
            * 1 byte depth:
                - 0x00 for master nodes,
                - 0x01 for level-1 descendants, ....
            * 4 byte fingerprint of the parent's key (0x00000000 if master key)
            * 4 byte child number. This is the number i in x_i = x_{par}/i,
              with x_i the key being serialized. This is encoded in MSB order.
              (0x00000000 if master key)
            * 32 bytes: the chain code
            * 33 bytes: the public key or private key data
              (0x02 + X or 0x03 + X for public keys, 0x00 + k for private keys)
              (Note that this also supports 0x04 + X + Y uncompressed points,
              but this is totally non-standard and this library won't even
              generate such data.)
        """
        key=bytes(key,"latin1")
        if len(key) in [78, (78 + 32)]:
            # we have a byte array, so pass
            pass
        else:
            key = ensure_bytes(key)
            if len(key) in [78 * 2, (78 + 32) * 2]:
                # we have a hexlified non-base58 key, continue!
                key = unhexlify(key)
            elif len(key) == 111:
                # We have a base58 encoded string
                key = base58.b58decode_check(key)
        # Now that we double checkd the values, convert back to bytes because
        # they're easier to slice
        version, depth, parent_fingerprint, child, chain_code, key_data = (
            key[:4], key[4], key[5:9], key[9:13], key[13:45], key[45:])

        version_long = long_or_int(hexlify(version), 16)
        exponent = None
        pubkey = None
        point_type = key_data[0]
        if not isinstance(point_type, six.integer_types):
            point_type = ord(point_type)
        if point_type == 0:
            # Private key
            if version_long != network.EXT_SECRET_KEY:
                raise ValueError("%s extended secret key %s doesn't match provided %s" % (
                    network.NAME, hex(network.EXT_SECRET_KEY),
                    hex(version_long)))
            exponent = key_data[1:]
        elif point_type in [2, 3, 4]:
            # Compressed public coordinates
            if version_long != network.EXT_PUBLIC_KEY:
                raise ValueError("%s extended public key %s doesn't match provided %s" % (
                    network.NAME, hex(network.EXT_PUBLIC_KEY),
                    hex(version_long)))
            pubkey = PublicKey.from_hex_key(key_data, network=network)
            # Even though this was generated from a compressed pubkey, we
            # want to store it as an uncompressed pubkey
            pubkey.compressed = False
        else:
            raise ValueError("Invalid key_data prefix, got %s" % point_type)

        def l(byte_seq):
            if byte_seq is None:
                return byte_seq
            elif isinstance(byte_seq, six.integer_types):
                return byte_seq
            return long_or_int(hexlify(byte_seq), 16)

        return cls(depth=l(depth),
                   parent_fingerprint=l(parent_fingerprint),
                   child_number=l(child),
                   chain_code=l(chain_code),
                   private_exponent=l(exponent),
                   public_key=pubkey,
                   network=network)
    def get_private_key_hex(self):
        """
        Get the hex-encoded (I guess SEC1?) representation of the private key.

        DO NOT share this private key with anyone.
        """
        return ensure_bytes(self.private_key.get_key())

    def get_public_key_hex(self, compressed=True):
        """Get the sec1 representation of the public key."""
        return ensure_bytes(self.public_key.get_key(compressed))

    @property
    def identifier(self):
        """Get the identifier for this node.

        Extended keys can be identified by the Hash160 (RIPEMD160 after SHA256)
        of the public key's `key`. This corresponds exactly to the data used in
        traditional Bitcoin addresses. It is not advised to represent this data
        in base58 format though, as it may be interpreted as an address that
        way (and wallet software is not required to accept payment to the chain
        key itself).
        """
        key = self.get_public_key_hex()
        return ensure_bytes(hexlify(hash160(unhexlify(ensure_bytes(key)))))

    @lru_cache(maxsize=1024)
    def get_child(self, child_number, is_prime=None, as_private=True):
        """Derive a child key.

        :param child_number: The number of the child key to compute
        :type child_number: int
        :param is_prime: If True, the child is calculated via private
            derivation. If False, then public derivation is used. If None,
            then it is figured out from the value of child_number.
        :type is_prime: bool, defaults to None
        :param as_private: If True, strips private key from the result.
            Defaults to False. If there is no private key present, this is
            ignored.
        :type as_private: bool

        Positive child_numbers (>= 0, < 2,147,483,648) produce publicly
        derived children. (prime=False)

        Negative numbers (> -2,147,483,648, < 0) use private derivation.
        (prime=True)

        NOTE: Python can't do -0, so if you want the privately derived 0th
        child you need to manually set is_prime=True.

        NOTE: negative numbered children are provided as a convenience
        because nobody wants to remember the above numbers. Negative numbers
        are considered 'prime children', which is described in the BIP32 spec
        as a leading 1 in a 32 bit unsigned int.

        This derivation is fully described at
        https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#child-key-derivation-functions  # nopep8
        """
        boundary = 0x80000000

        # Note: If this boundary check gets removed, then children above
        # the boundary should use private (prime) derivation.
        if abs(child_number) >= boundary:
            raise ValueError("Invalid child number %s" % child_number)

        # If is_prime isn't set, then we can infer it from the child_number
        if is_prime is None:
            # Prime children are either < 0 or > 0x80000000
            if child_number < 0:
                child_number = abs(child_number)
                is_prime = True
            else:
                is_prime = False
        else:
            # Otherwise is_prime is set so the child_number should be between
            # 0 and 0x80000000
            if child_number < 0 or child_number >= boundary:
                raise ValueError(
                    "Invalid child number. Must be between 0 and %s" %
                    boundary)

        if not self.private_key and is_prime:
            raise ValueError(
                "Cannot compute a prime child without a private key")

        child_number_hex = long_to_hex(child_number, 8)

        data = self.get_public_key_hex()
        data += child_number_hex

        # Compute a 64 Byte I that is the HMAC-SHA512, using self.chain_code
        # as the seed, and data as the message.
        I = hmac.new(
            unhexlify(ensure_bytes(self.chain_code)),
            msg=unhexlify(ensure_bytes(data)),
            digestmod=sha512).digest()
        # Split I into its 32 Byte components.
        I_L, I_R = I[:32], I[32:]

        if long_or_int(hexlify(I_L), 16) >= SECP256k1.order:
            raise InvalidPrivateKeyError("The derived key is too large.")

        c_i = hexlify(I_R)
        private_exponent = None
        public_pair = None
        if self.private_key:
            # Use private information for derivation
            # I_L is added to the current key's secret exponent (mod n), where
            # n is the order of the ECDSA curve in use.
            private_exponent = (
                (long_or_int(hexlify(I_L), 16) +
                 long_or_int(self.private_key.get_key(), 16))
                % SECP256k1.order)
            # I_R is the child's chain code

        child = self.__class__(
            chain_code=c_i,
            depth=self.depth + 1,  # we have to go deeper...
            parent_fingerprint=self.fingerprint,
            child_number=child_number_hex,
            private_exponent=private_exponent,
            public_pair=public_pair,
            network=self.network)
        if child.public_key.to_point() == INFINITY:
            raise InfinityPointException("The point at infinity is invalid.")
        return child

    @classmethod
    def from_master_secret(cls, seed, network=BitcoinMainNet):
        """Generate a new PrivateKey from a secret key.

        :param seed: The key to use to generate this wallet. It may be a long
            string. Do not use a phrase from a book or song, as that will
            be guessed and is not secure. My advice is to not supply this
            argument and let me generate a new random key for you.

        See https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Serialization_format  # nopep8
        """
        seed = ensure_bytes(seed)
        # Given a seed S of at least 128 bits, but 256 is advised
        # Calculate I = HMAC-SHA512(key="Bitcoin seed", msg=S)
        I = hmac.new(b"Bitcoin seed", msg=seed, digestmod=sha512).digest()
        # Split I into two 32-byte sequences, IL and IR.
        I_L, I_R = I[:32], I[32:]
        # Use IL as master secret key, and IR as master chain code.
        return cls(private_exponent=long_or_int(hexlify(I_L), 16),
                   chain_code=long_or_int(hexlify(I_R), 16),
                   network=network)


    def __eq__(self, other):
        attrs = [
            'chain_code',
            'depth',
            'parent_fingerprint',
            'child_number',
            'private_key',
            'public_key',
            'network',
        ]
        return other and all(
            getattr(self, attr) == getattr(other, attr) for attr in attrs)

    def __ne__(self, other):
        return not self == other

    __hash__ = object.__hash__

    @classmethod
    def new_random_wallet(cls, user_entropy=None, network=BitcoinMainNet):
        """
        Generate a new wallet using a randomly generated 512 bit seed.

        Args:
            user_entropy: Optional user-supplied entropy which is combined
                combined with the random seed, to help counteract compromised
                PRNGs.

        You are encouraged to add an optional `user_entropy` string to protect
        against a compromised CSPRNG. This will be combined with the output
        from the CSPRNG. Note that if you do supply this value it only adds
        additional entropy and will not be sufficient to recover the random
        wallet. If you're even saving `user_entropy` at all, you're doing it
        wrong.
        """
        seed = str(urandom(64))  # 512/8
        # weak extra protection inspired by pybitcointools implementation:
        seed += str(int(time.time()*10**6))
        if user_entropy:
            user_entropy = str(user_entropy)  # allow for int/long
            seed += user_entropy
        return cls.from_master_secret(seed, network=network)

string_types = (str)
string_or_bytes_types = (str, bytes)
int_types = (int, float)

# Base switching
code_strings = {
    2: '01',
    10: '0123456789',
    16: '0123456789abcdef',
    32: 'abcdefghijklmnopqrstuvwxyz234567',
    58: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
    256: ''.join([chr(x) for x in range(256)])
}
def bin_dbl_sha256(s):
    bytes_to_hash = from_string_to_bytes(s)
    return hashlib.sha256(hashlib.sha256(bytes_to_hash).digest()).digest()

def lpad(msg, symbol, length):
    if len(msg) >= length:
        return msg
    return symbol * (length - len(msg)) + msg

def get_code_string(base):
    if base in code_strings:
        return code_strings[base]
    else:
        raise ValueError("Invalid base!")

def changebase(string, frm, to, minlen=0):
    if frm == to:
        return lpad(string, get_code_string(frm)[0], minlen)
    return encode(decode(string, frm), to, minlen)

def from_int_to_byte(a):
    return bytes([a])

def from_byte_to_int(a):
    return a

def from_string_to_bytes(a):
    return a if isinstance(a, bytes) else bytes(a, 'utf-8')

def encode(val, base, minlen=0):
    base, minlen = int(base), int(minlen)
    code_string = get_code_string(base)
    result_bytes = bytes()
    while val > 0:
        curcode = code_string[val % base]
        result_bytes = bytes([ord(curcode)]) + result_bytes
        val //= base

    pad_size = minlen - len(result_bytes)

    padding_element = b'\x00' if base == 256 else b'1' \
        if base == 58 else b'0'
    if (pad_size > 0):
        result_bytes = padding_element*pad_size + result_bytes

    result_string = ''.join([chr(y) for y in result_bytes])
    result = result_bytes if base == 256 else result_string

    return result

def decode(string, base):
    if base == 256 and isinstance(string, str):
        try:  # Maybe its already in hex
            string = bytes(bytearray.fromhex(string), "utf-8")
        except ValueError as e:
            string = bytes(string, "utf-8")
    base = int(base)
    code_string = get_code_string(base)
    result = 0
    if base == 256:
        def extract(d, cs):
            return d
    else:
        def extract(d, cs):
            return cs.find(d if isinstance(d, str) else chr(d))

    if base == 16:
        string = string.lower()
    while len(string) > 0:
        result *= base
        result += extract(string[0], code_string)
        string = string[1:]
    return result

def bin_to_b58check(inp, magicbyte=0):
    inp_fmtd = from_int_to_byte(int(magicbyte))+inp

    leadingzbytes = 0
    for x in inp_fmtd:
        if x != 0:
            break
        leadingzbytes += 1

    checksum = bin_dbl_sha256(inp_fmtd)[:4]
    return '1' * leadingzbytes + changebase(inp_fmtd+checksum, 256, 58)

def b58check_to_bin(inp):
    leadingzbytes = len(re.match('^1*', inp).group(0))
    data = b'\x00' * leadingzbytes + changebase(inp, 58, 256)
    assert bin_dbl_sha256(data[:-4])[:4] == data[-4:]
    return data[1:-4]

# Elliptic curve parameters (secp256k1)
secp256k1 = {
    "P": 2**256 - 2**32 - 977,
    "N": 115792089237316195423570985008687907852837564279074904382605163141518161494337,
    "A": 0,
    "B": 7,
    "Gx": 55066263022277343669578718895168534326250603453777594175500187360389116729240,
    "Gy": 32670510020758816978083085130507043184471273380659243275938904335757337482424,
}

def get_pubkey_format(pub):
    two = 2
    three = 3
    four = 4

    if isinstance(pub, (tuple, list)):
        return 'decimal'
    elif len(pub) == 65 and pub[0] == four:
        return 'bin'
    elif len(pub) == 130 and pub[0:2] == '04':
        return 'hex'
    elif len(pub) == 33 and pub[0] in [two, three]:
        return 'bin_compressed'
    elif len(pub) == 66 and pub[0:2] in ['02', '03']:
        return 'hex_compressed'
    elif len(pub) == 64:
        return 'bin_electrum'
    elif len(pub) == 128:
        return 'hex_electrum'
    else:
        raise Exception("Pubkey not in recognized format")
def get_privkey_format(priv):
    if isinstance(priv, int_types):
        return 'decimal'
    elif len(priv) == 32:
        return 'bin'
    elif len(priv) == 33:
        return 'bin_compressed'
    elif len(priv) == 64:
        return 'hex'
    elif len(priv) == 66:
        return 'hex_compressed'
    else:
        bin_p = b58check_to_bin(priv)
        if len(bin_p) == 32:
            return 'wif'
        elif len(bin_p) == 33:
            return 'wif_compressed'
        else:
            raise Exception("WIF does not represent privkey")

def compress(pubkey):
    f = get_pubkey_format(pubkey)
    if 'compressed' in f:
        return pubkey
    elif f == 'bin':
        return encode_pubkey(decode_pubkey(pubkey, f), 'bin_compressed')
    elif f == 'hex' or f == 'decimal':
        return encode_pubkey(decode_pubkey(pubkey, f), 'hex_compressed')


def decompress(pubkey):
    f = get_pubkey_format(pubkey)
    if 'compressed' not in f:
        return pubkey
    elif f == 'bin_compressed':
        return encode_pubkey(decode_pubkey(pubkey, f), 'bin')
    elif f == 'hex_compressed' or f == 'decimal':
        return encode_pubkey(decode_pubkey(pubkey, f), 'hex')

def decode_pubkey(pub, formt=None):
    if not formt:
        formt = get_pubkey_format(pub)
    if formt == 'decimal':
        return pub
    elif formt == 'bin':
        return (decode(pub[1:33], 256), decode(pub[33:65], 256))
    elif formt == 'bin_compressed':
        x = decode(pub[1:33], 256)
        A, B, P = secp256k1['A'], secp256k1['B'], secp256k1['P']
        beta = pow(int(x*x*x+A*x+B), int((P+1)//4), int(P))
        y = (P-beta) if ((beta + from_byte_to_int(pub[0])) % 2) else beta
        return (x, y)
    elif formt == 'hex':
        return (decode(pub[2:66], 16), decode(pub[66:130], 16))
    elif formt == 'hex_compressed':
        return decode_pubkey(safe_from_hex(pub), 'bin_compressed')
    elif formt == 'bin_electrum':
        return (decode(pub[:32], 256), decode(pub[32:64], 256))
    elif formt == 'hex_electrum':
        return (decode(pub[:64], 16), decode(pub[64:128], 16))
    else:
        raise Exception("Invalid format!")


def encode_pubkey(pub, formt):
    if not isinstance(pub, (tuple, list)):
        pub = decode_pubkey(pub)
    if formt == 'decimal':
        return pub
    elif formt == 'bin':
        return b'\x04' + encode(pub[0], 256, 32) + encode(pub[1], 256, 32)
    elif formt == 'bin_compressed':
        return from_int_to_byte(2+(pub[1] % 2)) + encode(pub[0], 256, 32)
    elif formt == 'hex':
        return '04' + encode(pub[0], 16, 64) + encode(pub[1], 16, 64)
    elif formt == 'hex_compressed':
        return '0'+str(2+(pub[1] % 2)) + encode(pub[0], 16, 64)
    elif formt == 'bin_electrum':
        return encode(pub[0], 256, 32) + encode(pub[1], 256, 32)
    elif formt == 'hex_electrum':
        return encode(pub[0], 16, 64) + encode(pub[1], 16, 64)
    else:
        raise Exception("Invalid format!")

def decode_privkey(priv,formt=None):
    if not formt:
        formt = get_privkey_format(priv)
    if formt == 'decimal':
        return priv
    elif formt == 'bin':
        return decode(priv, 256)
    elif formt == 'bin_compressed':
        return decode(priv[:32], 256)
    elif formt == 'hex':
        return decode(priv, 16)
    elif formt == 'hex_compressed':
        return decode(priv[:64], 16)
    elif formt == 'wif':
        return decode(b58check_to_bin(priv),256)
    elif formt == 'wif_compressed':
        return decode(b58check_to_bin(priv)[:32],256)
    else:
        raise Exception("WIF does not represent privkey")


def encode_privkey(priv, formt, vbyte=0):
    if not isinstance(priv, int_types):
        return encode_privkey(decode_privkey(priv), formt, vbyte)
    if formt == 'decimal':
        return priv
    elif formt == 'bin':
        return encode(priv, 256, 32)
    elif formt == 'bin_compressed':
        return encode(priv, 256, 32)+b'\x01'
    elif formt == 'hex':
        return encode(priv, 16, 64)
    elif formt == 'hex_compressed':
        return encode(priv, 16, 64)+'01'
    elif formt == 'wif':
        return bin_to_b58check(encode(priv, 256, 32), 128+int(vbyte))
    elif formt == 'wif_compressed':
        return bin_to_b58check(encode(priv, 256, 32)+b'\x01', 128+int(vbyte))
    else:
        raise Exception("Invalid format!")

def extract_bin_chain_path(chain_path):
    if len(chain_path) == 64:
        return unhexlify(chain_path)
    elif len(chain_path) == 32:
        return chain_path
    else:
        raise ValueError('Invalid chain path')

def hash_to_int(x):
    if len(x) in [40, 64]:
        # decode as hex string
        return decode(x, 16)

    # decode as byte string
    return decode(x, 256)

MAINNET_PRIVATE = b'\x04\x88\xAD\xE4'
MAINNET_PUBLIC = b'\x04\x88\xB2\x1E'
TESTNET_PRIVATE = b'\x04\x35\x83\x94'
TESTNET_PUBLIC = b'\x04\x35\x87\xCF'
PRIVATE = [MAINNET_PRIVATE, TESTNET_PRIVATE]
PUBLIC = [MAINNET_PUBLIC, TESTNET_PUBLIC]

def bip32_serialize(rawtuple):
    """
    Derived from code from pybitcointools (https://github.com/vbuterin/pybitcointools)
    by Vitalik Buterin
    """
    vbytes, depth, fingerprint, i, chaincode, key = rawtuple
    i = encode(i, 256, 4)
    chaincode = encode(hash_to_int(chaincode), 256, 32)
    if isinstance(fingerprint, str):
        fingerprint = bytes(fingerprint, "latin1")
    if isinstance(chaincode, str):
        chaincode = bytes(chaincode, "latin1")
    if isinstance(vbytes, str):
        vbytes = bytes(vbytes, "latin1")
    keydata = b'\x00'  +key[:-1] if vbytes in PRIVATE else key
    bindata = vbytes + from_int_to_byte(depth % 256) + fingerprint + i + chaincode + keydata
    #return changebase(bindata + bin_dbl_sha256(bindata)[:4], 256, 58)
    return bindata.decode("latin1")


EXTENDED_PRIVATE_KEY_VERSION_BYTES = '\x04\x88\xad\xe4' # spells out 'xprv'

class PrivateKeychain():
    def __init__(self, private_keychain=None):
        if private_keychain:
            if isinstance(private_keychain, Wallet):
                self.hdkeychain = private_keychain
            elif isinstance(private_keychain, str):
                self.hdkeychain = Wallet.deserialize(private_keychain)
            else:
                raise ValueError('private keychain must be a string')
        else:
            self.hdkeychain = Wallet.new_random_wallet()

    def hardened_child(self, index):
        child_keychain = self.hdkeychain.get_child(
            index, is_prime=True, as_private=True)
        return PrivateKeychain(child_keychain)

    def private_key(self, compressed=True):
        private_key = self.hdkeychain.get_private_key_hex().decode('latin1')
        if compressed:
            private_key += '01'
        return private_key

    @classmethod
    def from_private_key(cls, private_key, chain_path='\x00'*32, depth=0,
                         fingerprint='\x00'*4, child_index=0):
        private_key_bytes = encode_privkey(private_key, 'bin_compressed')
        chain_path = extract_bin_chain_path(chain_path)
        keychain_parts = (EXTENDED_PRIVATE_KEY_VERSION_BYTES, depth, fingerprint,
                          child_index, chain_path, private_key_bytes)
        public_keychain_string = bip32_serialize(keychain_parts)
        return PrivateKeychain(public_keychain_string)

def bin_sha256(bin_s):
    if isinstance(bin_s, str):
        bin_s=bytes(bin_s, "latin1")
    return sha256(bin_s).digest()


def bin_checksum(bin_s):
    """ Takes in a binary string and returns a checksum. """
    return bin_sha256(bin_sha256(bin_s))[:4]


HEX_KEYSPACE = "0123456789abcdef"
B58_KEYSPACE = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check_encode(bin_s, version_byte=0):
    """ Takes in a binary string and converts it to a base 58 check string. """
    if isinstance(bin_s, str):
        bin_s=bytes(bin_s, "latin1")
    # append the version byte to the beginning
    bin_s = bytes(chr(int(version_byte)),"latin1") + bin_s
    # calculate the number of leading zeros
    num_leading_zeros = len(re.match(r'^\x00*', bin_s.decode("latin1")).group(0))
    # add in the checksum add the end
    bin_s = bin_s + bin_checksum(bin_s)
    # convert from b2 to b16
    hex_s = hexlify(bin_s)
    # convert from b16 to b58
    bin_s = bin_s.decode("latin1")
    hex_s = hex_s.decode("latin1")
    b58_s = change_charset(hex_s, HEX_KEYSPACE, B58_KEYSPACE)

    return B58_KEYSPACE[0] * num_leading_zeros + b58_s


def b58check_unpack(b58_s):
    """ Takes in a base 58 check string and returns: the version byte, the
        original encoded binary string, and the checksum.
    """
    num_leading_zeros = len(re.match(r'^1*', b58_s).group(0))
    # convert from b58 to b16
    hex_s = change_charset(b58_s, B58_KEYSPACE, HEX_KEYSPACE)
    # if an odd number of hex characters are present, add a zero to the front
    if len(hex_s) % 2 == 1:
        hex_s = "0" + hex_s
    # convert from b16 to b2
    bin_s = unhexlify(hex_s)
    # add in the leading zeros
    bin_s = '\x00' * num_leading_zeros + bin_s
    # make sure the newly calculated checksum equals the embedded checksum
    newly_calculated_checksum = bin_checksum(bin_s[:-4])
    embedded_checksum = bin_s[-4:]
    if not (newly_calculated_checksum == embedded_checksum):
        raise ValueError('b58check value has an invalid checksum')
    # return values
    version_byte = bin_s[:1]
    encoded_value = bin_s[1:-4]
    checksum = bin_s[-4:]
    return version_byte, encoded_value, checksum


def b58check_decode(b58_s):
    """ Takes in a base 58 check string and returns the original encoded binary
        string.
    """
    version_byte, encoded_value, checksum = b58check_unpack(b58_s)
    return encoded_value


PUBKEY_MAGIC_BYTE = b'\x04'


class CharEncoding():
    hex = 16
    bin = 256


class PubkeyType():
    ecdsa = 1
    uncompressed = 2
    compressed = 3


def address_to_bin_hash160(address):
    return b58check_decode(address)

def get_public_key_format(public_key_string):
    if isinstance(public_key_string, bytes):
        public_key_string = public_key_string.decode('latin1')
    if not isinstance(public_key_string, str):
        raise ValueError('Public key must be a string.')

    if len(public_key_string) == 64:
        return CharEncoding.bin, PubkeyType.ecdsa

    if (len(public_key_string) == 65 and
            public_key_string[0] == PUBKEY_MAGIC_BYTE):
        return CharEncoding.bin, PubkeyType.uncompressed

    if len(public_key_string) == 33:
        return CharEncoding.bin, PubkeyType.compressed

    if is_hex(public_key_string):
        if len(public_key_string) == 128:
            return CharEncoding.hex, PubkeyType.ecdsa

        if (len(public_key_string) == 130 and
                public_key_string[0:2] == hexlify(PUBKEY_MAGIC_BYTE)):
            return CharEncoding.hex, PubkeyType.uncompressed

        if len(public_key_string) == 66:
            return CharEncoding.hex, PubkeyType.compressed

    raise ValueError(_errors['IMPROPER_PUBLIC_KEY_FORMAT'])


def extract_bin_ecdsa_pubkey(public_key):
    key_charencoding, key_type = get_public_key_format(public_key)

    if key_charencoding == CharEncoding.hex:
        bin_public_key = unhexlify(public_key)
    elif key_charencoding == CharEncoding.bin:
        bin_public_key = public_key
    else:
        raise ValueError(_errors['IMPROPER_PUBLIC_KEY_FORMAT'])

    if key_type == PubkeyType.ecdsa:
        return bin_public_key
    elif key_type == PubkeyType.uncompressed:
        return bin_public_key[1:]
    elif key_type == PubkeyType.compressed:
        return decompress(bin_public_key)[1:]
    else:
        raise ValueError(_errors['IMPROPER_PUBLIC_KEY_FORMAT'])


def extract_bin_bitcoin_pubkey(public_key):
    key_charencoding, key_type = get_public_key_format(public_key)

    if key_charencoding == CharEncoding.hex:
        bin_public_key = unhexlify(public_key)
    elif key_charencoding == CharEncoding.bin:
        bin_public_key = public_key
    else:
        raise ValueError(_errors['IMPROPER_PUBLIC_KEY_FORMAT'])

    if key_type == PubkeyType.ecdsa:
        return PUBKEY_MAGIC_BYTE + bin_public_key
    elif key_type == PubkeyType.uncompressed:
        return bin_public_key
    elif key_type == PubkeyType.compressed:
        return bin_public_key
    else:
        raise ValueError(_errors['IMPROPER_PUBLIC_KEY_FORMAT'])

def get_bin_hash160(s, hex_format=False):
    """ s is in hex or binary format
    """
    if hex_format and is_hex(s):
        s = unhexlify(s)
    return hashlib.new('ripemd160', bin_sha256(s)).digest()


def random_secret_exponent(curve_order):
    """ Generates a random secret exponent. """
    # run a rejection sampling algorithm to ensure the random int is less
    # than the curve order
    while True:
        # generate a random 256 bit hex string
        random_hex = hexlify(dev_random_entropy(32))
        random_int = int(random_hex, 16)
        if random_int >= 1 and random_int < curve_order:
            break
    return random_int


def is_secret_exponent(val, curve_order):
    return (isinstance(val, (int, long)) and val >= 1 and val < curve_order)


def bin_hash160_to_address(bin_hash160, version_byte=0):
    if isinstance(bin_hash160, bytes):
        bin_hash160 = bin_hash160.decode("latin1")
    return b58check_encode(bin_hash160, version_byte=version_byte)

class BitcoinPublicKey():
    _curve = ecdsa.curves.SECP256k1
    _version_byte = 0

    @classmethod
    def version_byte(cls):
        return cls._version_byte

    def __init__(self, public_key_string, version_byte=None, verify=True):
        """ Takes in a public key in hex format.
        """
        # set the version byte
        if version_byte:
            self._version_byte = version_byte

        self._charencoding, self._type = get_public_key_format(
            public_key_string)

        # extract the binary bitcoin key (compressed/uncompressed w magic byte)
        self._bin_public_key = extract_bin_bitcoin_pubkey(public_key_string)

        # extract the bin ecdsa public key (uncompressed, w/out a magic byte)
        bin_ecdsa_public_key = extract_bin_ecdsa_pubkey(public_key_string)
        if verify:
            try:
                # create the ecdsa key object
                self._ecdsa_public_key = VerifyingKey.from_string(
                    bin_ecdsa_public_key, self._curve)
            except AssertionError as e:
                raise ValueError('IMPROPER_PUBLIC_KEY_FORMAT')

    def to_bin(self):
        return self._bin_public_key

    def to_hex(self):
        return hexlify(self.to_bin())
    def bin_hash160(self):

        if not hasattr(self, '_bin_hash160'):
            self._bin_hash160 = get_bin_hash160(self.to_bin())
        return self._bin_hash160

    def hash160(self):
        return hexlify(self.bin_hash160())

    def address(self):
        if self._type == PubkeyType.compressed:
            bin_hash160 = get_bin_hash160(compress(self.to_bin()))
            return bin_hash160_to_address(
                bin_hash160, version_byte=self._version_byte)

        return bin_hash160_to_address(self.bin_hash160(),
                                      version_byte=self._version_byte)

class BitcoinPrivateKey():
    _curve = ecdsa.curves.SECP256k1
    _hash_function = hashlib.sha256
    _pubkeyhash_version_byte = 0

    def __init__(self, private_key=None, compressed=False):
        """ Takes in a private key/secret exponent.
        """
        self._compressed = compressed
        if not private_key:
            secret_exponent = random_secret_exponent(self._curve.order)
        else:
            secret_exponent = encode_privkey(private_key, 'decimal')
            if get_privkey_format(private_key).endswith('compressed'):
                self._compressed = True

        # make sure that: 1 <= secret_exponent < curve_order
        if not is_secret_exponent(secret_exponent, self._curve.order):
            raise IndexError("EXPONENT_OUTSIDE_CURVE_ORDER")

        self._ecdsa_private_key = ecdsa.keys.SigningKey.from_secret_exponent(
            secret_exponent, self._curve, self._hash_function
        )

    def to_bin(self):
        if self._compressed:
            return encode_privkey(
                self._ecdsa_private_key.to_string(), 'bin_compressed')
        else:
            return self._ecdsa_private_key.to_string()

    def to_hex(self):
        if self._compressed:
            return encode_privkey(
                self._ecdsa_private_key.to_string(), 'hex_compressed')
        else:
            return hexlify(self.to_bin())
        
    def to_wif(self):
        if self._compressed:
            return encode_privkey(
                self._ecdsa_private_key.to_string(), 'wif_compressed', vbyte=self._pubkeyhash_version_byte)
        else:
            return b58check_encode(
                self.to_bin(), version_byte=self.wif_version_byte())

    def public_key(self):
        # lazily calculate and set the public key
        if not hasattr(self, '_public_key'):
            ecdsa_public_key = self._ecdsa_private_key.get_verifying_key()

            bin_public_key_string = PUBKEY_MAGIC_BYTE + \
                ecdsa_public_key.to_string()

            if self._compressed:
                bin_public_key_string = compress(bin_public_key_string)

            # create the public key object from the public key string
            self._public_key = BitcoinPublicKey(
                bin_public_key_string,
                version_byte=self._pubkeyhash_version_byte)

        # return the public key object
        return self._public_key


# modified from example at https://gist.github.com/sekondus/4322469
# the block size for the cipher object; must be 16, 24, or 32 for AES
BLOCK_SIZE = 32

# the character used for padding--with a block cipher such as AES, the value
# you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
# used to ensure that your value is always a multiple of BLOCK_SIZE
PADDING = '{'
DPADDING = b'{'
# one-liner to sufficiently pad the text to be encrypted
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

# one-liners to encrypt/encode and decrypt/decode a string
# encrypt with AES, encode with base64
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(DPADDING)

def ensure_length(secret):
    if len(secret) > 32:
        secret = secret[:32]

    elif len(secret) < 24:
        length = 24 - (len(secret) % 24)
        secret += bytes(chr(length)*length, "utf-8")
    elif len(secret) > 24 and len(secret) < 32:
        length = 32 - (len(secret) % 32)
        secret += bytes(chr(length)*length, "utf-8")

    return hexlify(secret)

def get_new_secret():
    secret = os.urandom(BLOCK_SIZE)
    return hexlify(secret)


def aes_encrypt(payload, secret):
    secret = ensure_length(secret)

    cipher = AES.new(unhexlify(secret))
    return EncodeAES(cipher, payload).decode("utf-8")


def aes_decrypt(payload, secret):
    secret = ensure_length(secret)

    cipher = AES.new(unhexlify(secret))
    return DecodeAES(cipher, payload).decode("utf-8")


def get_addresses_from_privkey(hex_privkey):
    """ get both bitcoin and namecoin addresses
    """

    #nmc_privkey = NamecoinPrivateKey(hex_privkey)
    btc_privkey = BitcoinPrivateKey(hex_privkey)

    #nmc_pubkey = nmc_privkey.public_key()
    #nmc_address = nmc_pubkey.address()

    btc_pubkey = btc_privkey.public_key()
    btc_address = btc_pubkey.address()

    return None, btc_address # We do not need NMC but we also dont want to break sonething


def get_address_from_pubkey(hex_pubkey):
    """ get bitcoin address from pub key
    """

    pubkey = BitcoinPublicKey(hex_pubkey)

    return pubkey.address()


def get_address_from_privkey(hex_privkey):
    """ get bitcoin address from private key
    """

    privkey = BitcoinPrivateKey(hex_privkey)

    pubkey = privkey.public_key()
    return pubkey.address()


def get_pubkey_from_privkey(hex_privkey):
    """ get bitcoin address from private key
    """

    privkey = BitcoinPrivateKey(hex_privkey)

    pubkey = privkey.public_key()
    return pubkey.to_hex()



class HDWallet(object):

    """
        Initialize a hierarchical deterministic wallet with
        hex_privkey and get child addresses and private keys
    """

    def __init__(self, hex_privkey=None, enable_cache=False):

        """
            If @hex_privkey is given, use that to derive keychain
            otherwise, use a new random seed
        """

        if hex_privkey:
            self.priv_keychain = PrivateKeychain.from_private_key(hex_privkey)
        else:
            self.priv_keychain = PrivateKeychain()

        self.master_address = self.get_master_address()
        self.child_addresses = None


    def get_master_privkey(self):

        return self.priv_keychain.private_key()

    def get_child_privkey(self, index=0):
        """
            @index is the child index

            Returns:
            child privkey for given @index
        """

        child = self.priv_keychain.hardened_child(index)
        return child.private_key()

    def get_master_address(self):

        hex_privkey = self.get_master_privkey()
        return get_address_from_privkey(hex_privkey)

    def get_child_address(self, index=0):
        """
            @index is the child index

            Returns:
            child address for given @index
        """

        if self.child_addresses is not None:
            return self.child_addresses[index]

        hex_privkey = self.get_child_privkey(index)
        return get_address_from_privkey(hex_privkey)

    def get_child_keypairs(self, count=1, offset=0, include_privkey=False):
        """
            Returns (privkey, address) keypairs

            Returns:
            returns child keypairs

            @include_privkey: toggles between option to return
                             privkeys along with addresses or not
        """

        keypairs = []

        for index in range(offset, offset+count):
            address = self.get_child_address(index)

            if include_privkey:
                hex_privkey = self.get_child_privkey(index)
                keypairs.append((address, hex_privkey))
            else:
                keypairs.append(address)

        return keypairs



def main():

    result = {}
    print("Blockstack Legacy wallet private key extractor by NotATether")
    print("-----")
    print("")
    mode = sys.argv[1]
    if mode == "extract":
        if len(sys.argv) != 3:
            print("Usage: blockstack-recover extract /path/to/wallet.json")
            sys.exit(1)
        extract()
    elif mode == "decrypt":
        if len(sys.argv) != 4:
            print("Usage: blockstack-recover decrypt encrypted-wallet.json output-wallet.json")
            sys.exit(1)
    else:
        print("Usage: blockstack-recover [decrypt|extract] ARGS")
        sys.exit(1)
    decrypt()

def decrypt():
    src = sys.argv[2]
    dest = sys.argv[3]
    print("Opening wallet file %s..." % src)
    f_src = open(src)
    jwallet = json.load(f_src)
    f_src.close()
    encrypted_key = jwallet['encrypted_master_private_key']
    data = {}
    correct_decryption = False
    while not correct_decryption:
        secret = getpass.getpass(prompt="Enter wallet password: ")
        hex_password = hexlify(bytes(secret, "utf-8"))
        try:
            hex_privkey = aes_decrypt(encrypted_key, hex_password)
            correct_decryption=True
            break
        except (ValueError, KeyError) as e:
            print("Incorrect password")
    data['master_private_key'] = hex_privkey
    data['wallet_password'] = secret
    print("Dumping decryted wallet to %s" % (dest))
    print("")
    print("-----")
    print("master_private_key:", hex_privkey)
    print("wallet_password:", secret)
    f_dest = open(dest,'w')
    f_dest.write(json.dumps(data))
    f_dest.close() 
    sys.exit(0)

def extract():
    src = sys.argv[2]
    #dest = sys.argv[3]

    print("Opening wallet file %s..." % src)
    f_src = open(src)
    jwallet = json.load(f_src)
    print("Deriving master private key...")
    hex_privkey = jwallet["master_private_key"]
    password = jwallet["wallet_password"]
    hex_password = hexlify(bytes(password, "utf-8"))

    wallet = HDWallet(hex_privkey)
    child = wallet.get_child_keypairs(count=3, include_privkey=False)
   

    hex_privkey_1 = wallet.get_child_privkey(1)
    btc_1 = get_address_from_privkey(hex_privkey_1)
    btc_privkey_1 = BitcoinPrivateKey(hex_privkey_1)
    wif_1 = btc_privkey_1.to_wif()
   
    hex_privkey_2 = wallet.get_child_privkey(0)
    btc_2 = get_address_from_privkey(hex_privkey_2)
    btc_privkey_2 = BitcoinPrivateKey(hex_privkey_2)
    wif_2 = btc_privkey_2.to_wif()

    hex_privkey_3 = wallet.get_child_privkey(2)
    btc_3 = get_address_from_privkey(hex_privkey_3)
    btc_privkey_3 = BitcoinPrivateKey(hex_privkey_3)
    wif_3 = btc_privkey_3.to_wif()

   
    master = wallet.get_master_privkey()
    btc_privkey = BitcoinPrivateKey(hex_privkey)
    priv_hex = btc_privkey.to_hex()
    priv_wif = btc_privkey.to_wif()

    btc = get_address_from_privkey(hex_privkey)
    btc_pub = get_pubkey_from_privkey(hex_privkey)

    #data = {}
    #encrypted_key = aes_encrypt(hex_privkey, hex_password)
    #data['encrypted_master_private_key'] = encrypted_key
    #data['payment_addresses'] = [child[0]]
    #data['owner_addresses'] = [child[1]]

    #file = open(dest, 'w')
    #file.write(json.dumps(data))
    #file.close()
    print("")
    print("Dumping wallet info: Make sure to import payment_WIF")
    print("")
    print("-----")
    print("master_private_key:", hex_privkey)
    print("wallet_password:", password)
    print("-----")
    print("")
    print("-----")
    #print("encrypted_master_private_key:", encrypted_key)
    #print("-----")
    print("owner_addresses:", [child[1]])
    print("owner_addresses:", btc_1)
    print("owner_key_hex:", hex_privkey_1)
    print("WIF owner:", wif_1)
    print("-----")
    print("payment_addresses:", [child[0]])
    print("payment_addresses:", btc_2)
    print("payment_key_hex", hex_privkey_2)
    print("WIF payment:", wif_2)
    print("-----")
    print("payment_addresses:", [child[2]])
    print("payment_addresses:", btc_3)
    print("payment_key_hex", hex_privkey_3)
    print("WIF payment:", wif_3)
    print("-----")
    print("")
    print("FROM MASTER")
    print("Address:", btc)
    print("Priv HEX:", priv_hex)
    print("WIF Master:", priv_wif)
    sys.exit(0)

if __name__ == "__main__":
    main()
