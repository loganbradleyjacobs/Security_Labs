# Logan Jacobs
# CSC-348 Computer Security
# 1/24/26

from cryptology.ciph_utils import Utils, Symbol_Set

def caesar_cipher(message: str, shift: int, encrypt:bool, symbols: Symbol_Set = Symbol_Set((32, 126))) -> str:
    '''Allows encrypting or decrypting an arbitrary message by a arbitrary shift using the caesar cipher method'''
    return Utils.shift_message(message, shift, symbols) if encrypt else Utils.shift_message(message, -shift, symbols)

def main():
    # 1.1
    shift = 5
    message = "Hello World"
    C = caesar_cipher(message, shift, True)
    M = caesar_cipher(C, shift, False)
    print("(1.1)--------------------------------")
    print(f"Message: {message}")
    print(f"Ciphertext: {C}")
    print(f"Decoded Message: {M}")

if __name__ == "__main__":
    main()