from AES import AES
from RSA import RSA
from Bifid import Bifid

#RSA test
print("----------------------------")
rsa = RSA()
message = "hello"

encoded_message = rsa.encode_message(message)
print("Input message :")
print(message)
print("Encoded message :")
print(''.join(str(p) for p in encoded_message))
print("Decoded message :")
print(rsa.decode_message(encoded_message))

#AES test
print("----------------------------")
key = b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x97\x95\x8d\x6e\x61\x7d'
data = b'\x32\x43\xf6\xa8\x88\x5a\x30\x8d\x31\x31\x98\xa2\xe0\x37\x07\x34'
aes = AES(key)
aes.test_encryption_decryption_string(key,message)

#Hill Cypher test
print("----------------------------")
hillCypher = Bifid()
# Encrypting the user message
message = message.upper()
encrypted = hillCypher.encrypt(message)

# Printing the encrypted message
print(f"Encrypted message with Hill Cypher: {encrypted}")

# Decrypting the previously encrypted message
decrypted = hillCypher.decrypt(encrypted)

# Printing the decrypted message
print(f"Decrypted message with Hill Cypher: {decrypted}")



