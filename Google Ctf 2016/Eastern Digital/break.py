import pyelliptic
from Crypto.Cipher import AES
import base64
import itertools

RNG_STATE = 1

def seed_rng(seed, len):
	global RNG_STATE
	RNG_STATE = 1
	i = 0
	while i < len:
		RNG_STATE ^= ord(seed[i])
		i += 1

	return i

def random_byte():
	global RNG_STATE
	RNG_STATE = (RNG_STATE >> 1) | (((((RNG_STATE >> 4) ^ ((RNG_STATE >> 3) ^ (RNG_STATE >> 2) ^ RNG_STATE)) & 1) << 7) & 0xFF);
	return RNG_STATE

def derive_key(passwd, len):
	h = pyelliptic.pbkdf2(passwd, passwd, 31337, 16)[1]
	seed_rng(h, len)
	res = ''
	for i in xrange(16):
		res += chr(random_byte())

	return res

def encrypt(key, plain):
	e = AES.new(key , AES.MODE_CBC, '\x00'*16)
	padd_len = (16 - (len(plain)%16))
	plain = plain + padd_len*chr(padd_len)
	return e.encrypt(plain)

def decrypt(key, cipher):
	d = AES.new(key , AES.MODE_CBC, '\x00'*16)
	plain_with_padding = d.decrypt(cipher)
	padd_char = ord(plain_with_padding[-1])
	plain = plain_with_padding[0:-padd_char]
	return plain

if __name__ == '__main__':
	CIPHER = base64.b64decode('Yh99elDYtDcUQQdZ6K2kCLc/MhXi7RcsxLq8FNDXNdfUqH7o6kkppI5eg9Ad2X4q')
	PASS_CHARS = '1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
	for p in itertools.product(PASS_CHARS, repeat=2):
		key = derive_key(''.join(p), 16)
		plain = decrypt(key, CIPHER)
		if plain[0:3] == 'CTF':
			print 'Success !'
			print 'Password -',p
			print 'Flag -',plain
