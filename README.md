# DES
DES - Data Encryption Standart - symmetric key-algorithm for the encryption electronic data.(unsecure, more info on wikipedia)
3DES - Triple DES - TDEA - symmetric-key block cipher, enforced by increasing size of key (56,112,168 bits according key1=key2=key3; key1=key3, but not key2; key1!=key2!=key3, key1!=key3). 

# 3DES algorithm description:
encryption operations
  I -> E(k1) -> D(k2) -> E(k3) -> O
decryption operations
  I -> D(k3) -> E(k2) -> D(k1) -> O
