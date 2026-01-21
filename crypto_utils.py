################################################################################################################

# Copyright (c) 2026 by Uwe Martens * www.namecoin.pro * https://dotbit.app

################################################################################################################

import hashlib
import hmac
import struct
import binascii
import base64
import ecdsa
from ecdsa import SigningKey, SECP256k1
from ecdsa.ellipticcurve import Point
from ecdsa.numbertheory import inverse_mod
from ecdsa.util import sigencode_der_canonize, sigdecode_der

NAMECOIN_WIF_PREFIX = b'\xb4'
NAMECOIN_P2SH_PREFIX = b'\x0d'
B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
SECP_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
SECP_N = SECP256k1.order
SECP_CURVE = SECP256k1.curve
SECP_G = SECP256k1.generator

# ---------------- Base58 decode ----------------
def b58decode(s: str) -> bytes:
	n = 0
	for ch in s:
		n = n * 58 + B58_ALPHABET.index(ch)
	full = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n != 0 else b''
	leading = 0
	for ch in s:
		if ch == B58_ALPHABET[0]:
			leading += 1
		else:
			break
	return b'\x00' * leading + full

# ---------------- Base58 encode ----------------
def b58encode(b: bytes) -> str:
	n = int.from_bytes(b, "big")
	res = bytearray()
	while n > 0:
		n, r = divmod(n, 58)
		res.append(ord(B58_ALPHABET[r]))
	leading = 0
	for c in b:
		if c == 0:
			leading += 1
		else:
			break
	if res:
		return B58_ALPHABET[0] * leading + bytes(reversed(res)).decode()
	else:
		return B58_ALPHABET[0] * leading

# ---------------- Base58check decode ----------------
def base58check_decode(s: str) -> bytes:
	raw = b58decode(s)
	if len(raw) < 5:
		raise ValueError("Too short for base58check")
	payload, chk = raw[:-4], raw[-4:]
	if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != chk:
		raise ValueError("Invalid checksum")
	return payload

# ---------------- Base58check encode ----------------
def base58check_encode(payload: bytes) -> str:
	chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
	return b58encode(payload + chk)

# ---------------- Priv to WIF ----------------
def priv_to_wif(priv_bytes: bytes, compressed=True) -> str:
	payload = NAMECOIN_WIF_PREFIX + priv_bytes
	if compressed:
		payload += b'\x01'
	return base58check_encode(payload)

# ---------------- Compute PubKey from priv ----------------
def compute_pubkey_from_priv(priv: bytes, compressed=True):
	sk = SigningKey.from_string(priv, curve=SECP256k1)
	vk = sk.verifying_key
	if compressed:
		prefix = b'\x02' if vk.to_string()[-1] % 2 == 0 else b'\x03'
		return (prefix + vk.to_string()[:32]).hex()
	else:
		return '04' + vk.to_string().hex()

# ---------------- Compute PubKey from WIF ----------------
def compute_pubkey_from_wif(wif: str):
	dec = base58check_decode(wif)
	priv = dec[1:]
	compressed = False
	if len(priv) == 33 and priv[-1] == 1:
		priv = priv[:-1]
		compressed = True
	return compute_pubkey_from_priv(priv, compressed)

# ---------------- Parse path ----------------
def parse_path(path_str: str):
	if not path_str:
		return []
	if path_str.startswith('m'):
		path_str = path_str[1:]
		if path_str.startswith('/'):
			path_str = path_str[1:]
	parts = path_str.split('/') if path_str else []
	path = []
	for p in parts:
		if not p:
			continue
		hardened = p.endswith('h') or p.endswith("'") or p.endswith("H")
		if hardened:
			p = p[:-1]
		try:
			idx = int(p)
		except Exception:
			continue
		if hardened:
			idx += 2**31
		path.append(idx)
	return path

# ---------------- Compute fingerprint from xprv ----------------
def compute_fingerprint_from_xprv(xprv: str):
	dec = base58check_decode(xprv)
	if len(dec) != 78:
		return None
	key = dec[45:]
	if key[0] != 0:
		return None
	priv = key[1:]
	pub = compute_pubkey_from_priv(priv)
	h = hashlib.sha256(bytes.fromhex(pub)).digest()
	rip = hashlib.new('ripemd160', h).digest()
	return rip[:4].hex()

# ---------------- Derive priv ----------------
def derive_priv(xpriv: str, relative_path: list):
	dec = base58check_decode(xpriv)
	if len(dec) != 78:
		return None
	chaincode = dec[13:45]
	key = dec[45:]
	if key[0] != 0:
		return None
	current_priv = key[1:]
	current_chaincode = chaincode
	for idx in relative_path:
		hardened = idx >= 2**31
		if hardened:
			data = b'\x00' + current_priv + struct.pack(">I", idx)
		else:
			sk = SigningKey.from_string(current_priv, curve=SECP256k1)
			vk = sk.verifying_key
			prefix = b'\x02' if vk.to_string()[-1] % 2 == 0 else b'\x03'
			pub = prefix + vk.to_string()[:32]
			data = pub + struct.pack(">I", idx)
		I = hmac.new(current_chaincode, data, hashlib.sha512).digest()
		Il, Ir = I[:32], I[32:]
		il_int = int.from_bytes(Il, 'big')
		if il_int >= SECP_N:
			return None
		child_int = (il_int + int.from_bytes(current_priv, 'big')) % SECP_N
		if child_int == 0:
			return None
		current_priv = child_int.to_bytes(32, 'big')
		current_chaincode = Ir
	return current_priv

# ---------------- Derive WIF ----------------
def try_derive_wif(priv, pubkey):
	if priv:
		for compressed in [True, False]:
			pubcalc = compute_pubkey_from_priv(priv, compressed)
			if pubcalc.lower() == pubkey:
				return priv_to_wif(priv, compressed)
	return None

# ---------------- Encode varint ----------------
def encode_varint(i):
	if i < 0xFD:
		return i.to_bytes(1, 'big')
	elif i <= 0xFFFF:
		return b'\xFD' + i.to_bytes(2, 'little')
	elif i <= 0xFFFFFFFF:
		return b'\xFE' + i.to_bytes(4, 'little')
	else:
		return b'\xFF' + i.to_bytes(8, 'little')

# ---------------- Hash160 ----------------
def hash160(b):
	return hashlib.new('ripemd160', hashlib.sha256(b).digest()).digest()

# ---------------- Bech32 polymod ----------------
def bech32_polymod(values):
	GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
	chk = 1
	for v in values:
		b = chk >> 25
		chk = (chk & 0x1ffffff) << 5 ^ v
		for i in range(5):
			if (b >> i) & 1:
				chk ^= GEN[i]
	return chk

# ---------------- Bech32 HRP expand ----------------
def bech32_hrp_expand(s):
	return [ord(x) >> 5 for x in s] + [0] + [ord(x) & 31 for x in s]

# ---------------- Bech32 create checksum ----------------
def bech32_create_checksum(hrp, data):
	values = bech32_hrp_expand(hrp) + data
	mod = bech32_polymod(values + [0,0,0,0,0,0]) ^ 1
	return [(mod >> 5 * (5 - i)) & 31 for i in range(6)]

# ---------------- Bech32 encode ----------------
def bech32_encode(hrp, data):
	charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
	combined = data + bech32_create_checksum(hrp, data)
	return hrp + '1' + ''.join([charset[d] for d in combined])

# ---------------- Convert bits ----------------
def convertbits(data, frombits, tobits, pad=True):
	acc = 0
	bits = 0
	ret = []
	maxv = (1 << tobits) - 1
	max_acc = (1 << (frombits + tobits - 1)) - 1
	for value in data:
		if value < 0 or (value >> frombits):
			return None
		acc = ((acc << frombits) | value) & max_acc
		bits += frombits
		while bits >= tobits:
			bits -= tobits
			ret.append((acc >> bits) & maxv)
	if pad:
		if bits:
			ret.append((acc << (tobits - bits)) & maxv)
	elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
		return None
	return ret

# ---------------- SegWit addr encode ----------------
def segwit_addr_encode(hrp, witver, witprog):
	data = [witver] + convertbits(witprog, 8, 5)
	if data is None:
		raise ValueError("Invalid witprog for convertbits")
	return bech32_encode(hrp, data)

# ---------------- Recover PubKey ----------------
def recover_pubkey(r, s, rec_id, z):
	if rec_id < 0 or rec_id > 3:
		return None
	x = r
	if rec_id & 2:
		x += SECP_N
	if x >= SECP_P:
		return None
	xx = x * x * x + 7
	beta = pow(xx, (SECP_P + 1) // 4, SECP_P)
	even_beta = beta % 2 == 0
	if (rec_id & 1) == 1:
		y = SECP_P - beta if even_beta else beta
	else:
		y = beta if even_beta else SECP_P - beta
	if pow(y, 2, SECP_P) != xx % SECP_P:
		return None
	R = Point(SECP_CURVE, x, y)
	r_inv = inverse_mod(r, SECP_N)
	QR = (R * s + SECP_G * ((-z) % SECP_N)) * r_inv
	return QR
