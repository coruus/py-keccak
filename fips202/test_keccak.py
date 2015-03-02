from keccak import Keccak, Sha3_224, Sha3_256, Sha3_384, Sha3_512, \
  Shake128, Shake256

TEST_F1600_ZERO = """\
F1258F7940E1DDE7 84D5CCF933C0478A D598261EA65AA9EE BD1547306F80494D 8B284E056253D057
FF97A42D7F8E6FD4 90FEE5A0A44647C4 8C5BDA0CD6192E76 AD30A6F71B19059C 30935AB7D08FFC64
EB5AA93F2317D635 A9A6E6260D712103 81A57C16DBCF555F 43B831CD0347C826 01F22F1A11A5569F
05E5635A21D9AE61 64BEFEF28CC970F2 613670957BC46611 B87C5A554FD00ECB 8C3EE88A1CCF32C8
940C7922AE3A2614 1841F924A2C509E4 16F53526E70465C2 75F644E97F30A13B EAF1FF7B5CECA249\
""".lower().replace('0', '-')

def test_f1600_zero():
  k = Keccak()
  k.F1600()
  assert TEST_F1600_ZERO == repr(k)

test_f1600_zero()

from binascii import unhexlify as unhx
from json import load
kats = load(open('keccakKats.json', 'r'))['kats']
FOF = {'SHA3-224': Sha3_224, 'SHA3-256': Sha3_256, 'SHA3-384': Sha3_384, 'SHA3-512': Sha3_512}
VOF = {'SHAKE128': Shake128, 'SHAKE256': Shake256}

for k, f in FOF.items():
  for kat in kats[k]:
    l = kat['length'] // 8
    m = unhx(kat['message'])
    d = bytes(kat['digest'].lower().decode('utf-8'))
    h = f().update(m[:l]).hexdigest()
    if h != d:
      print("FAIL ", k, l)
      print(h, kat['digest'].lower())
      break

for k, f in VOF.items():
  for kat in kats[k]:
    l = kat['length'] // 8
    m = unhx(kat['message'])
    d = bytes(kat['digest'].lower().decode('utf-8'))
    h = f().update(m[:l]).hexdigest(512)
    if h != d:
      print("FAIL ", k, l)
      print(h, kat['digest'].lower())
      break
