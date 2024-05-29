import random
import math

# Note
"""
   RSA implements a basic encryption and decryption algorithm using the RSA method. 
   
   It includes functionality to generate prime numbers, select random primes, 
   generate public and private keys, and encode/decode messages.
   
   The class initializes a set of prime numbers, generates keys, and provides methods 
   for encrypting and decrypting messages.
   
"""

class RSA:
    def __init__(self):
        self.prime_numbers = set()
        self.public_exponent = None
        self.private_exponent = None
        self.modulus = None
        self.generate_primes()
        self.generate_keys()

    def generate_primes(self):
        """
        Initializing a set of prime numbers less than 250
        """
        sieve = [True] * 250
        sieve[0] = False
        sieve[1] = False
        for i in range(2, 250):
            for j in range(i * 2, 250, i):
                sieve[j] = False

        for i in range(len(sieve)):
            if sieve[i]:
                self.prime_numbers.add(i)

    def select_random_prime(self):
        """
        Selecting a random prime from the generated set
        """
        index = random.randint(0, len(self.prime_numbers) - 1)
        iterator = iter(self.prime_numbers)
        for _ in range(index):
            next(iterator)

        prime = next(iterator)
        self.prime_numbers.remove(prime)
        return prime

    def generate_keys(self):
        """
        Generating the public and private keys (exponents in our case)
        """
        prime1 = self.select_random_prime()
        prime2 = self.select_random_prime()

        self.modulus = prime1 * prime2
        totient = (prime1 - 1) * (prime2 - 1)

        candidate_exponent = 2
        while True:
            if math.gcd(candidate_exponent, totient) == 1:
                break
            candidate_exponent += 1

        self.public_exponent = candidate_exponent

        candidate_private_exponent = 2
        while True:
            if (candidate_private_exponent * self.public_exponent) % totient == 1:
                break
            candidate_private_exponent += 1

        self.private_exponent = candidate_private_exponent

    def encrypt_message(self, message):
        """
        Encrypting a message using the public key and modulus
        """
        exponent = self.public_exponent
        cipher_text = 1
        while exponent > 0:
            cipher_text *= message
            cipher_text %= self.modulus
            exponent -= 1
        return cipher_text

    def decrypt_message(self, encrypted_text):
        """
        Decrypting the message using the private key and modulus
        """
        exponent = self.private_exponent
        decrypted_text = 1
        while exponent > 0:
            decrypted_text *= encrypted_text
            decrypted_text %= self.modulus
            exponent -= 1
        return decrypted_text

    def encode_message(self, message):
        """
        Converting the message chars into the integer values and encrypting each integer using the public key
        """
        encoded_message = []
        for character in message:
            encoded_message.append(self.encrypt_message(ord(character)))
        return encoded_message

    def decode_message(self, encoded_message):
        """
        Decrypting each integer in the message using the private key and converting the integers to characters
        """
        decoded_string = ''
        for number in encoded_message:
            decoded_string += chr(self.decrypt_message(number))
        return decoded_string
