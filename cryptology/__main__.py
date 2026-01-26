# Logan Jacobs
# CSC-348 Computer Security
# 1/26/26
'''Sources:
chatGPT explained why i need __init__.py for module creation, and why __main__.py is useful
'''
from cryptology.caesar_cipher import main as caesar_cipher_main
from cryptology.vigenere_cipher import main as vigenere_cipher_main
from cryptology.cryptanalysis import main as cryptanalysis_main

if __name__ == "__main__":
    caesar_cipher_main()
    vigenere_cipher_main()
    cryptanalysis_main()
