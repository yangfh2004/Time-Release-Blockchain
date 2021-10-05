"""
Implementation of the ElGamal Cryptosystem
Author: Ryan Riddle (ryan.riddle@uky.edu)
Date of Completion: April 20, 2012

Revised by Fanghao Yang (yangfanghao@gmail.com)
Date of Revision: Oct 1, 2021

REVISION

Revision has been done to clean up the code, add type hints, add enough docstring, rename
names of arguments and methods based on PEP-8.

DESCRIPTION AND IMPLEMENTATION

This python program implements the ElGamal crypto-system.  The program is capable of both
encrypting and decrypting a message.  At execution the user will be prompted for three things:
       1) a number n which specifies the length of the prime to be generated
       2) a number t which specifies the desired confidence that the generated prime is actually prime
       3) a string that contains the message he wishes to encrypt and decrypt

After the user has provided the necessary information the program will generate a pair
of keys (K1, K2) used for encryption and decryption.  K1 is the public key and contains
three integers (p, g, h).
       p is an n bit prime.  The probability that p is actually prime is 1-(2^-t)
       g is the square of a primitive root mod p
       h = g^x mod p; x is randomly chosen, 1 <= x < p
h is computed using fast modular exponentiation, implemented as mod_exp ( base, exp, modulus )
K2 is the private key and contains three integers (p, g, x) that are described above.
K1 and K2 are written to files named K1 and K2.

Next the program encodes the bytes of the message into integers z[i] < p.
The module for this is named encode() and is described further where it is implemented.

After the message has been encoded into integers, the integers are encrypted and written
to a file, Ciphertext.  The encryption procedure is implemented in encrypt().  It works
as follows:
       Each corresponds to a pair (c, d) that is written to Ciphertext.
       For each integer z[i]:
               c[i] = g^y (mod p).  d[i] = z[i]h^y (mod p)
               where y is chosen randomly, 0 <= y < p

The decryption module decrypt() reads each pair of integers from Ciphertext and converts
them back to encoded integers.  It is implemented as follows:
       s = c[i]^x (mod p)
       z[i] = d[i]*s^-1 (mod p)

The decode() module takes the integers produced from the decryption module and separates
them into the bytes received in the initial message.  These bytes are written to the file
Plaintext.

HURDLES CLEARED DURING IMPLEMENTATION

modular exponentiation
The first problem I encountered was in implementing the fast modular exponentiator, mod_exp().
At first it did not terminate when given a negative number.  I quickly figured out that when
performing integer division on negative numbers, the result is rounded down rather than toward
zero.

finding primitive roots
Understanding the definition of primitive roots was not enough to find one efficiently.  I had
search the web to understand how primitive roots can be found.  Wikipedia helped me understand
I needed to test potential primitive roots multiplicative order.  The algorithm found at
http://modular.math.washington.edu/edu/2007/spring/ent/ent-html/node31.html
is the one I implemented.

finding large prime numbers
After implementing the Solovay-Strassen primality test I found it was difficult to compute 100
bit primes even with probability 1/2.  I met with Professor Klapper to discuss this problem and he
suggested I quit running the program on UK's shared "multilab" and I speed up my Jacobi algorithm
by using branches to find powers of -1 rather than actually exponentiating them.  After doing this
I was able to find 500 bit primes in about 15 minutes.

finding prime numbers with confidence > 2
I found it took a long time to test primes with a large number of bits with confidence greater than
two.  I went to the web again to read over the description of the Solovay-Strassen primality test
and realized jacobi(a, n) should be congruent to mod_exp(a, (n-1)/2, n) mod n.  I had only been checking
that they were equal.  Before making this change I tried to find a 200 bit prime with confidence 100
and gave up after an hour and a half.  After this change I was able to succeed after a couple of minutes.
getting encoding and decoding to work

I knew that encoding and decoding were implemented correctly because I could encode and decode a message
and get the message I had started with.  But I did not receive the right message when I encrypted and
decrypted it, despite having checked my encrypt and decrypt modules many times.  I fixed this by raising
s to p-2 instead of -1 in the decryption function.
"""
from typing import Optional
from simpleTimeReleaseBlockchain.crypto.elgamal_util import *


class PrivateKey(object):
    def __init__(self, p: int, g: int, x: int, bit_length=0):
        """Init private key structure for elgamal encryption.

        Args:
            p: a large prime number
            g: a generator
            x: a randomly chosen key
            bit_length: bit length of the prime number
        """
        self.p = p
        self.g = g
        self.x = x
        self.bit_length = bit_length

    def __eq__(self, other):
        if self.p == other.p and self.g == other.g and self.x == other.x and self.bit_length == other.bit_length:
            return True
        else:
            return False


class PublicKey(object):
    def __init__(self, p: int, g: int, h: int, bit_length=0):
        """Init public key structure for elgamal encryption.

        Args:
            p: a large prime number
            g: a generator
            h:
            bit_length: bit length of the prime number
        """
        self.p = p
        self.g = g
        self.h = h
        self.bit_length = bit_length
        # optional attribute to carry its paired private key
        self.x = None

    def __eq__(self, other):
        if self.p == other.p and self.g == other.g and self.h == other.h and self.bit_length == other.bit_length:
            return True
        else:
            return False


def encode(s_plaintext: str, bit_length: int) -> list[int]:
    """Encodes bytes to integers mod p.
    Example
    if n = 24, k = n / 8 = 3
    z[0] = (summation from i = 0 to i = k)m[i]*(2^(8*i))
    where m[i] is the ith message byte

    Args:
        s_plaintext: String text to be encoded
        bit_length: bit length of the prime number

    Returns:
        A list of encoded integers
    """
    byte_array = bytearray(s_plaintext, 'utf-16')

    # z is the array of integers mod p
    z = []

    # each encoded integer will be a linear combination of k message bytes
    # k must be the number of bits in the prime divided by 8 because each
    # message byte is 8 bits long
    k = bit_length // 8

    # j marks the jth encoded integer
    # j will start at 0 but make it -k because j will be incremented during first iteration
    j = -1 * k
    # num is the summation of the message bytes
    # num = 0
    # i iterates through byte array
    for idx in range(len(byte_array)):
        # if i is divisible by k, start a new encoded integer
        if idx % k == 0:
            j += k
            # num = 0
            z.append(0)
        # add the byte multiplied by 2 raised to a multiple of 8
        z[j // k] += byte_array[idx] * (2 ** (8 * (idx % k)))

    return z


def decode(encoded_integers: list[int], bit_length: int) -> str:
    """Decodes integers to the original message bytes.
    Example:
    if "You" were encoded.
    Letter        #ASCII
    Y              89
    o              111
    u              117
    if the encoded integer is 7696217 and k = 3
    m[0] = 7696217 % 256 % 65536 / (2^(8*0)) = 89 = 'Y'
    7696217 - (89 * (2^(8*0))) = 7696128
    m[1] = 7696128 % 65536 / (2^(8*1)) = 111 = 'o'
    7696128 - (111 * (2^(8*1))) = 7667712
    m[2] = 7667712 / (2^(8*2)) = 117 = 'u'

    Args:
        encoded_integers:
        bit_length: bit length of the prime number.

    Returns:
        Decoded message string.
    """
    # bytes array will hold the decoded original message bytes
    bytes_array = []

    # same deal as in the encode function.
    # each encoded integer is a linear combination of k message bytes
    # k must be the number of bits in the prime divided by 8 because each
    # message byte is 8 bits long
    k = bit_length // 8

    # num is an integer in list aiPlaintext
    for num in encoded_integers:
        # get the k message bytes from the integer, i counts from 0 to k-1
        for idx in range(k):
            # temporary integer
            temp = num
            # j goes from i+1 to k-1
            for j in range(idx + 1, k):
                # get remainder from dividing integer by 2^(8*j)
                temp = temp % (2 ** (8 * j))
            # message byte representing a letter is equal to temp divided by 2^(8*i)
            letter = temp // (2 ** (8 * idx))
            # add the message byte letter to the byte array
            bytes_array.append(letter)
            # subtract the letter multiplied by the power of two from num so
            # so the next message byte can be found
            num = num - (letter * (2 ** (8 * idx)))

    decoded_text = bytearray(b for b in bytes_array).decode('utf-16')

    return decoded_text


def generate_pub_key(seed: int, bit_length: int, i_confidence=32) -> PublicKey:
    """Generates public key K1 (p, g, h) and private key K2 (p, g, x).

    Args:
        seed:
        bit_length:
        i_confidence:

    Returns:

    """
    # p is the prime
    # g is the primitive root
    # x is random in (0, p-1) inclusive
    # h = g ^ x mod p

    p = find_prime(bit_length, i_confidence, seed)
    g = find_primitive_root(p, seed)
    # h = mod_exp(g, 2, p)
    # x = random.randint( 1, p - 1)
    # h = mod_exp(g,x,p)

    h = random.randint(1, p - 1)

    public_key = PublicKey(p, g, h, bit_length)
    # privateKey = PrivateKey(p, g, x, iNumBits)

    return public_key


def find_private_key(pubkey: PublicKey) -> Optional[PrivateKey]:
    """Find private key with brute force.

    Args:
        pubkey: public key to find its paired private key.

    Returns:
        paired private key
    """
    for x in range(2, pubkey.p - 1):
        if pubkey.h == mod_exp(pubkey.g, x, pubkey.p):
            return PrivateKey(pubkey.p, pubkey.g, x, bit_length=pubkey.bit_length)
    return None


def encrypt(key: PublicKey, s_plaintext: str) -> str:
    """Encrypts a string using the public key k.

    Args:
        key: public key for encryption
        s_plaintext: input message string

    Returns:
        Encrypted text string.
    """
    z = encode(s_plaintext, key.bit_length)

    # cipher_pairs list will hold pairs (c, d) corresponding to each integer in z
    cipher_pairs = []
    # i is an integer in z
    for i_code in z:
        # pick random y from (0, p-1) inclusive
        y = random.randint(0, key.p)
        # c = g^y mod p
        c = mod_exp(key.g, y, key.p)
        # d = ih^y mod p
        d = (i_code * mod_exp(key.h, y, key.p)) % key.p
        # add the pair to the cipher pairs list
        cipher_pairs.append([c, d])

    encrypted_str = ""
    for pair in cipher_pairs:
        encrypted_str += str(pair[0]) + ' ' + str(pair[1]) + ' '

    return encrypted_str


def decrypt(key: PrivateKey, cipher_string: str) -> str:
    """Performs decryption on the cipher pairs found in Cipher using
    private key K2 and writes the decrypted values to file Plaintext.

    Args:
        key: Private key to decrypt message string.
        cipher_string: encrypted cipher string.

    Returns:
        Decrypted message string.
    """
    # decrypts each pair and adds the decrypted integer to list of plaintext integers
    plaintext = []

    cipher_array = cipher_string.split()
    if not len(cipher_array) % 2 == 0:
        raise ValueError("Malformed Cipher Text")
    for idx in range(0, len(cipher_array), 2):
        # c = first number in pair
        c = int(cipher_array[idx])
        # d = second number in pair
        d = int(cipher_array[idx + 1])

        # s = c^x mod p
        s = mod_exp(c, key.x, key.p)
        # plaintext integer = ds^-1 mod p
        plain_i = (d * mod_exp(s, key.p - 2, key.p)) % key.p
        # add plain to list of plaintext integers
        plaintext.append(plain_i)

    decrypted_text = decode(plaintext, key.bit_length)

    # remove trailing null bytes
    decrypted_text = "".join([ch for ch in decrypted_text if ch != '\x00'])

    return decrypted_text
