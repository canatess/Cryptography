import math
import string
import numpy as np
from sympy import Matrix


# Create two dictionaries, english alphabet to numbers and numbers to english alphabet, and returns them
def get_alphabet():
    alphabet = {}
    for character in string.ascii_uppercase:
        alphabet[character] = string.ascii_uppercase.index(character)

    reverse_alphabet = {}
    for key, value in alphabet.items():
        reverse_alphabet[value] = key

    return alphabet, reverse_alphabet

# Get input from the user and checks if respects the alphabet
def get_text_input(message, alphabet):
    while True:
        text = input(message)
        text = text.upper()
        if all(keys in alphabet for keys in text):
            return text
        else:
            print("\nThe text must contain only characters from the english alphabet ([A to Z] or [a to z]).")


# Check if the key is a square in length
def is_square(key):
    key_length = len(key)
    if 2 <= key_length == int(math.sqrt(key_length)) ** 2:
        return True
    else:
        return False


# Create the matrix k for the key
def get_key_matrix(key, alphabet):
    k = list(key)
    m = int(math.sqrt(len(k)))
    for (i, character) in enumerate(k):
        k[i] = alphabet[character]

    return np.reshape(k, (m, m))


# Create the matrix of m-grams of a text, if needed, complete the last m-gram with the last letter of the alphabet
def get_text_matrix(text, m, alphabet):
    matrix = list(text)
    remainder = len(text) % m
    for (i, character) in enumerate(matrix):
        matrix[i] = alphabet[character]
    if remainder != 0:
        for i in range(m - remainder):
            matrix.append(25)

    return np.reshape(matrix, (int(len(matrix) / m), m)).transpose()


# Encrypt a Message and returns the ciphertext matrix
def encrypt(key, plaintext, alphabet):
    m = key.shape[0]
    m_grams = plaintext.shape[1]

    # Encrypt the plaintext with the key provided k, calculate matrix c of ciphertext
    ciphertext = np.zeros((m, m_grams)).astype(int)
    for i in range(m_grams):
        ciphertext[:, i] = np.reshape(np.dot(key, plaintext[:, i]) % len(alphabet), m)
    return ciphertext


# Transform a matrix to a text, according to the alphabet
def matrix_to_text(matrix, order, alphabet):
    if order == 't':
        text_array = np.ravel(matrix, order='F')
    else:
        text_array = np.ravel(matrix)
    text = ""
    for i in range(len(text_array)):
        text = text + alphabet[text_array[i]]
    return text


# Check if the key is invertible and in that case returns the inverse of the matrix
def get_inverse(matrix, alphabet):
    alphabet_len = len(alphabet)
    if math.gcd(int(round(np.linalg.det(matrix))), alphabet_len) == 1:
        matrix = Matrix(matrix)
        return np.matrix(matrix.inv_mod(alphabet_len))
    else:
        return None


# Decrypt a Message and returns the plaintext matrix
def decrypt(k_inverse, c, alphabet):
    return encrypt(k_inverse, c, alphabet)


def get_m():
    while True:
        try:
            m = int(input("Insert the length of the grams (m): "))
            if m >= 2:
                return m
            else:
                print("\nYou must enter a number m >= 2\n")
        except ValueError:
            print("\nYou must enter a number m >= 2\n")


# Force a Ciphertext (Known Plaintext Attack)
def plaintext_attack(c, p_inverse, alphabet):
    return encrypt(c, p_inverse, alphabet)


# Get two dictionaries, english alphabet to numbers and numbers to english alphabet
alphabet, reverse_alphabet = get_alphabet()

# Asks the user the text and the ciphertext to use them for the plaintext attack
plaintext = get_text_input("\nInsert the plaintext for the attack: ", alphabet)
ciphertext = get_text_input("Insert the ciphertext of the plaintext for the attack: ", alphabet)

# Asks the user the length of the grams
m = get_m()

if len(plaintext) / m >= m:
    # Get the m-grams matrix p of the plaintext and takes the firsts m
    p = get_text_matrix(plaintext, m, alphabet)
    p = p[:, 0:m]

    # Check if the matrix of the plaintext is invertible and in that case returns the inverse of the matrix
    p_inverse = get_inverse(p, alphabet)

    if p_inverse is not None:
        # Get the m-grams matrix c of the ciphertext
        c = get_text_matrix(ciphertext, m, alphabet)
        c = c[:, 0:m]

        if c.shape[1] == p.shape[0]:
            print(f"\nCiphertext Matrix \n{c}\n")
            print(f"Plaintext Matrix \n{p}")

            # Force the ciphertext provided
            k = plaintext_attack(c, p_inverse, alphabet)

            # Transform the key matrix to a text of the alphabet
            key = matrix_to_text(k, "k", reverse_alphabet)

            print("\nThe key has been found.\n")
            print(f"Generated Key: {key}\n")
            print(f"Generated Key Matrix\n{k}")