################################################################################################################

# Copyright (c) 2026 by Uwe Martens * www.namecoin.pro * https://dotbit.app

################################################################################################################

import re
import requests
import json
from collections import defaultdict
from crypto_utils import *
import hashlib

class Signer:
	def __init__(self, rpc_config):
		self.rpc = rpc_config
		self.hd_dict = defaultdict(list)
		self.pubkey_to_wif = {}
		self.is_descriptor = False
		self.load_descriptors()

	# ---------------- Load descriptors ----------------
	def load_descriptors(self):
		try:
			wallet_info = self.rpc_call('getwalletinfo', [])
			self.is_descriptor = wallet_info.get('descriptors', False)
			if self.is_descriptor:
				ld = self.rpc_call('listdescriptors', [True])
				descriptors_all = ld.get('descriptors', []) or []
				for d in descriptors_all:
					ds = d.get('desc')
					if ds:
						self.parse_descriptor_entry(ds)
					pd = d.get('parent_desc')
					if pd:
						self.parse_descriptor_entry(pd)
		except Exception as e:
			print("Error loading descriptors:", e)

	# ---------------- RPC call helper ----------------
	def rpc_call(self, method, params=[]):
		payload = json.dumps({"method": method, "params": params, "id": 1})
		headers = {'content-type': 'application/json'}
		auth = (self.rpc['user'], self.rpc['pass'])
		response = requests.post(self.rpc['url'], data=payload, headers=headers, auth=auth, timeout=10)
		response.raise_for_status()
		json_resp = response.json()
		if 'error' in json_resp and json_resp['error']:
			raise ValueError(json_resp['error']['message'])
		return json_resp['result']

	# ---------------- VarInt-Encoding (CompactSize) ----------------
	@staticmethod
	def varint(n):
		if n < 0xfd:
			return bytes([n])
		elif n <= 0xffff:
			return b'\xfd' + n.to_bytes(2, 'little')
		elif n <= 0xffffffff:
			return b'\xfe' + n.to_bytes(4, 'little')
		else:
			return b'\xff' + n.to_bytes(8, 'little')

	# ---------------- Message hash ----------------
	def message_hash(self, msg):
		magic = b"Namecoin Signed Message:\n"
		msg_bytes = msg.encode('utf-8')
		payload = self.varint(len(magic)) + magic + self.varint(len(msg_bytes)) + msg_bytes
		sha_once = hashlib.sha256(payload).digest()
		return hashlib.sha256(sha_once).digest()

	# ---------------- Get address from name ----------------
	def get_address_from_name(self, name):
		res = self.rpc_call('name_show', [name])
		addr = res.get('address')
		if not addr:
			raise ValueError("No address found for the given name")
		return addr

	# ---------------- Get PubKey-bytes ----------------
	def _get_pub_bytes(self, Q, compressed):
		if compressed:
			return (b'\x02' if Q.y() % 2 == 0 else b'\x03') + Q.x().to_bytes(32, 'big')
		else:
			return b'\x04' + Q.x().to_bytes(32, 'big') + Q.y().to_bytes(32, 'big')

	# ---------------- Sign message ----------------
	def sign(self, addr, msg):
		wif = self.get_wif(addr, for_signing=True)
		if not wif:
			raise ValueError("Cannot retrieve private key for address")

		dec = base58check_decode(wif)
		priv = dec[1:]
		compressed = False
		if len(priv) == 33 and priv[-1] == 1:
			priv = priv[:-1]
			compressed = True

		message_hash = self.message_hash(msg)

		sk = SigningKey.from_string(priv, curve=SECP256k1)
		sig_der = sk.sign_digest_deterministic(
			message_hash,
			hashfunc=hashlib.sha256,
			sigencode=sigencode_der_canonize
		)

		r, s = sigdecode_der(sig_der, SECP_N)
		r_bytes = r.to_bytes(32, 'big')
		s_bytes = s.to_bytes(32, 'big')
		z = int.from_bytes(message_hash, 'big')

		is_bech32 = addr.startswith('nc1')
		prefix = None
		is_p2sh = False
		if not is_bech32:
			dec_addr = base58check_decode(addr)
			prefix = dec_addr[0:1]
			is_p2sh = prefix in [NAMECOIN_P2SH_PREFIX, b'\xc4']

		for rec_id in range(4):
			Q = recover_pubkey(r, s, rec_id, z)
			if not Q:
				continue

			pub_bytes = self._get_pub_bytes(Q, compressed)
			v_base = 31 if compressed else 27

			h160 = hash160(pub_bytes)

			if is_bech32:
				computed_addr = segwit_addr_encode('nc', 0, h160)
			else:
				if is_p2sh:
					script = b'\x00\x14' + h160
					computed_addr = base58check_encode(prefix + hash160(script))
				else:
					computed_addr = base58check_encode(prefix + h160)

			if computed_addr == addr:
				v = v_base + rec_id
				sig_bytes = bytes([v]) + r_bytes + s_bytes
				return base64.b64encode(sig_bytes).decode('utf-8').rstrip('\n')

		raise ValueError("Could not compute valid signature")

	# ---------------- Verify message ----------------
	def verify(self, addr, sig, msg):
		sig_bytes = base64.b64decode(sig)
		if len(sig_bytes) != 65:
			raise ValueError("Invalid signature length")

		v = sig_bytes[0]
		r = int.from_bytes(sig_bytes[1:33], 'big')
		s = int.from_bytes(sig_bytes[33:65], 'big')
		if s > SECP_N // 2:
			return False

		if 27 <= v <= 30:
			rec_id = v - 27
			compressed = False
		elif 31 <= v <= 34:
			rec_id = v - 31
			compressed = True
		else:
			raise ValueError("Invalid recovery byte")

		message_hash = self.message_hash(msg)
		z = int.from_bytes(message_hash, 'big')

		Q = recover_pubkey(r, s, rec_id, z)
		if not Q:
			return False

		pub_bytes = self._get_pub_bytes(Q, compressed)

		h160 = hash160(pub_bytes)

		is_bech32 = addr.startswith('nc1')
		if is_bech32:
			computed_addr = segwit_addr_encode('nc', 0, h160)
		else:
			dec_addr = base58check_decode(addr)
			prefix = dec_addr[0:1]
			if prefix in [NAMECOIN_P2SH_PREFIX, b'\xc4']:
				computed_addr = base58check_encode(prefix + hash160(b'\x00\x14' + h160))
			else:
				computed_addr = base58check_encode(prefix + h160)

		return computed_addr == addr

	# ---------------- Get WIF ----------------
	def get_wif(self, addr, for_signing=True):
		if for_signing and not self.is_descriptor:
			try:
				return self.rpc_call('dumpprivkey', [addr])
			except Exception:
				pass

		info = self.rpc_call('getaddressinfo', [addr])
		pubkey = info.get('pubkey', "").lower()
		embedded = info.get('embedded', {})
		if not pubkey and embedded:
			pubkey = embedded.get('pubkey', "").lower()

		fingerprint = info.get('hdmasterfingerprint') or embedded.get('hdmasterfingerprint')
		hdkeypath = info.get('hdkeypath') or embedded.get('hdkeypath')
		wif = None

		# Direct pubkey -> WIF mapping
		if pubkey in self.pubkey_to_wif:
			wif = self.pubkey_to_wif[pubkey]

		# HD derivation
		if not wif and fingerprint and hdkeypath:
			full_path = parse_path(hdkeypath)

			# Matching path derivation
			for hd_info in self.hd_dict.get(fingerprint, []):
				matching_path = hd_info['matching_path']
				if len(full_path) >= len(matching_path) and full_path[:len(matching_path)] == matching_path:
					priv = derive_priv(hd_info['xprv'], full_path[len(matching_path):])
					wif = try_derive_wif(priv, pubkey)
					if wif:
						break

			# Fallback 1: origin-based derivation
			if not wif:
				for hd_info in self.hd_dict.get(fingerprint, []):
					priv = derive_priv(hd_info['xprv'], full_path[hd_info['origin_len']:])
					wif = try_derive_wif(priv, pubkey)
					if wif:
						break

			# Fallback 2: root derivation
			if not wif:
				for hd_info in self.hd_dict.get(fingerprint, []):
					if hd_info['origin_len'] == 0:
						priv = derive_priv(hd_info['xprv'], full_path)
						wif = try_derive_wif(priv, pubkey)
						if wif:
							break

		# Final fallback
		if not wif:
			try:
				wif = self.rpc_call('dumpprivkey', [addr])
			except Exception:
				pass

		return wif

	# ---------------- Parse descriptor entry ----------------
	def parse_descriptor_entry(self, desc_str):
		if not desc_str:
			return
		desc_n = desc_str.split('#')[0]

		nested = False
		if desc_n.startswith('sh(wpkh(') and desc_n.endswith('))'):
			key_part = desc_n[8:-2]
			nested = True
		elif desc_n.startswith('wpkh(') and desc_n.endswith(')'):
			key_part = desc_n[5:-1]
		elif desc_n.startswith('pkh(') and desc_n.endswith(')'):
			key_part = desc_n[4:-1]
		else:
			key_part = desc_n

		bracket_path_str = ''
		fingerprint = None
		ext_key = key_part

		m = re.match(r'^\[([0-9a-fA-F]{8})(/[^]]*)?\](.+)$', key_part)
		if m:
			fingerprint = m.group(1).lower()
			bracket_path_str = m.group(2) or ''
			ext_key = m.group(3)

		suffix_start = ext_key.find('/')
		extkey_root = ext_key if suffix_start == -1 else ext_key[:suffix_start]

		if extkey_root.startswith(('xprv', 'tprv', 'yprv', 'zprv', 'dprv')):
			suffix = ext_key[suffix_start:] if suffix_start != -1 else ''
			if suffix.endswith('/*'):
				suffix = suffix[:-2]
			origin = parse_path(bracket_path_str)
			suffix_fixed = parse_path(suffix)
			fp = fingerprint or compute_fingerprint_from_xprv(extkey_root)
			if fp:
				self.hd_dict[fp].append({
					'xprv': extkey_root,
					'origin_len': len(origin),
					'matching_path': origin + suffix_fixed,
					'nested': nested
				})
			return

		try:
			pub = compute_pubkey_from_wif(extkey_root)
			if pub:
				self.pubkey_to_wif[pub.lower()] = extkey_root
		except Exception:
			pass

	def cleanup(self):
		for fp in list(self.hd_dict.keys()):
			for entry in self.hd_dict[fp]:
				entry['xprv'] = None
		self.hd_dict.clear()
