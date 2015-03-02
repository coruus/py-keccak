"""Keccak and the FIPS202 functions."""
from __future__ import division, print_function

from base64 import urlsafe_b64encode
from binascii import hexlify
from functools import partial

import numpy as np


_KECCAK_RHO = [
     1,  3,  6, 10, 15, 21,
    28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43,
    62, 18, 39, 61, 20, 44]
_KECCAK_PI = [
    10,  7, 11, 17, 18, 3,
     5, 16,  8, 21, 24, 4,
    15, 23, 19, 13, 12, 2,
    20, 14, 22,  9,  6, 1]
_KECCAK_RC = np.array([
  0x0000000000000001, 0x0000000000008082,
  0x800000000000808a, 0x8000000080008000,
  0x000000000000808b, 0x0000000080000001,
  0x8000000080008081, 0x8000000000008009,
  0x000000000000008a, 0x0000000000000088,
  0x0000000080008009, 0x000000008000000a,
  0x000000008000808b, 0x800000000000008b,
  0x8000000000008089, 0x8000000000008003,
  0x8000000000008002, 0x8000000000000080,
  0x000000000000800a, 0x800000008000000a,
  0x8000000080008081, 0x8000000000008080,
  0x0000000080000001, 0x8000000080008008],
  dtype=np.uint64)

_SPONGE_ABSORBING = 1
_SPONGE_SQUEEZING = 2

def rol(x, s):
  """Rotate x left by s."""
  return ((np.uint64(x) << np.uint64(s)) ^ (np.uint64(x) >> np.uint64(64 - s)))





class Keccak(object):
  """The Keccak-F[1600] permutation."""

  def __init__(self) :
    self.state = np.zeros(25, dtype=np.uint64)

  def F1600(self):
    state = self.state
    bc = np.zeros(5, dtype=np.uint64)

    for i in range(24):
      # Parity
      for x in range(5):
        bc[x] = 0
        for y in range(0, 25, 5):
          bc[x] ^= state[x + y]

      # Theta
      for x in range(5):
        t = bc[(x + 4) % 5] ^ rol(bc[(x + 1) % 5], 1)
        for y in range(0, 25, 5):
          state[y + x] ^= t

      # Rho and pi
      t = state[1]
      for x in range(24):
        bc[0] = state[_KECCAK_PI[x]]
        state[_KECCAK_PI[x]] = rol(t, _KECCAK_RHO[x])
        t = bc[0]

      for y in range(0, 25, 5):
        for x in range(5):
          bc[x] = state[y + x]
        for x in range(5):
          state[y + x] = bc[x] ^ ((~bc[(x + 1) % 5]) & bc[(x + 2) % 5])

      state[0] ^= _KECCAK_RC[i]
    self.state = state

  def __repr__(self):
    state = self.state
    lines = []
    for x in range(0, 25, 5):
      lines.append(
        ' '.join('{:016x}'.format(state[x + y]).replace('0', '-')
                 for y in range(5)))
    return '\n'.join(lines)


class KeccakHash(object):

  def __init__(self, b='', rate=None, dsbyte=None):
    if rate < 0 or rate > 199:
      raise Exception("Invalid rate.")
    self.rate, self.dsbyte, self.i = rate, dsbyte, 0
    self.k = Keccak()
    self.buf = np.zeros(200, dtype=np.uint8)
    self.absorb(b)
    self.direction = _SPONGE_ABSORBING

  def absorb(self, b):
    todo = len(b)
    i = 0
    while todo > 0:
      cando = self.rate - self.i
      willabsorb = min(cando, todo)
      self.buf[self.i:self.i + willabsorb] ^= \
          np.frombuffer(b[i:i+willabsorb], dtype=np.uint8)
      self.i += willabsorb
      if self.i == self.rate:
        self.permute()
      todo -= willabsorb
      i += willabsorb

  def squeeze(self, n):
    tosqueeze = n
    b = b''
    while tosqueeze > 0:
      cansqueeze = self.rate - self.i
      willsqueeze = min(cansqueeze, tosqueeze)
      b += self.k.state.view(dtype=np.uint8)[self.i:self.i + willsqueeze].tostring()
      self.i += willsqueeze
      if self.i == self.rate:
        self.permute()
      tosqueeze -= willsqueeze
    return b

  def pad(self):
    self.buf[self.i] ^= self.dsbyte
    self.buf[self.rate - 1] ^= 0x80
    self.permute()

  def permute(self):
    self.k.state ^= self.buf.view(dtype=np.uint64)
    self.k.F1600()
    self.i = 0
    self.buf[:] = 0

  def update(self, b):
    if self.direction == _SPONGE_SQUEEZING:
      self.permute()
      self.direction == _SPONGE_ABSORBING
    self.absorb(b)
    return self

  def __repr__(self):
    return "KeccakHash(rate={}, dsbyte=0x{:02x})".format(self.rate, self.dsbyte)


class Sha3(KeccakHash):

  """An SHA-3 fixed-output-length function."""

  def digest(self):
    if self.direction == _SPONGE_ABSORBING:
      self.pad()
    return self.squeeze((200 - self.rate) // 2)

  def hexdigest(self):
    return hexlify(self.digest())

  def b64digest(self):
    return urlsafe_b64encode(self.digest())


class Shake(KeccakHash):

  """A SHAKE variable-output-length function."""

  def digest(self, n
             ):
    if self.direction == _SPONGE_ABSORBING:
      self.pad()
    return self.squeeze(n)

  def hexdigest(self, n):
    return hexlify(self.digest(n))

  def b64digest(self, n):
    return urlsafe_b64encode(self.digest(n))


Sha3_224 = partial(Sha3, rate=200-( 448 // 8), dsbyte=0x06)
Sha3_256 = partial(Sha3, rate=200-( 512 // 8), dsbyte=0x06)
Sha3_384 = partial(Sha3, rate=200-( 768 // 8), dsbyte=0x06)
Sha3_512 = partial(Sha3, rate=200-(1024 // 8), dsbyte=0x06)

Shake128 = partial(Shake, rate=200-(256 // 8), dsbyte=0x1f)
Shake256 = partial(Shake, rate=200-(512 // 8), dsbyte=0x1f)

ShakeX = partial(Shake, dsbyte=0x1f)

__all__ = [Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256, ShakeX]
