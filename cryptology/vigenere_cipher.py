# Logan Jacobs
# CSC-348 Computer Security
# 1/24/26

from cryptology.ciph_utils import Symbol_Set, Utils
from cryptology.caesar_cipher import caesar_cipher


def vigenere_cipher(
    message: str, keyword: str, encrypt: bool, symbols: Symbol_Set = None
) -> str:
    """Allows encrypting or decrypting an arbitrary message by a arbitrary keyword, using the vigenere cipher method"""
    if not keyword or not message:
        return message
    symbols = Utils.default_set(symbols)
    key_shifts = [symbols.index(k) for k in keyword]
    result = []
    direction = 1 if encrypt else -1

    for i, c in enumerate(message):
        message_index = symbols.index(c)
        shift = key_shifts[i % len(key_shifts)] * direction
        result.append(symbols[message_index + shift])
    return "".join(result)


def main():
    # 1.2
    keyword = "DeLaRiva"
    message = "Hello World"
    C = vigenere_cipher(
        message, keyword, True
    )  # symbol set is assumed to be printable ascii
    M = vigenere_cipher(
        C, keyword, False
    )  # same symbol set assumed here (see Symbol_Set._default_set())
    print("(1.2)--------------------------------")
    print(f"Message {message}")
    print(f"Ciphertext: {C}")
    print(f"Decoded Message: {M}")


if __name__ == "__main__":
    main()
