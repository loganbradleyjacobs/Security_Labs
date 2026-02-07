# Security Labs
- Labs for CSC-348: Computer Security
- **See [Github Pages deployment](https://loganbradleyjacobs.github.io/Security_Labs/) for documentation.**

## Assignment 1 (Cryptology)
Quick Use:
```
git clone https://github.com/loganbradleyjacobs/Security_Labs
cd Security_Labs
python -m cryptology.symmetric
```
Source code can be found in the `cryptology/symmetric` directory. Specific functions can also be inspected from the documentation.

### Description:
The above commands will clone the repo, change directories into the repo you just cloned locally, and run the `cryptology.symmetric` module.
The output shown will be that from simple tests meant to demonstrate core functionality of the functions. In Section 1.1 and 1.2, I demonstrate encryption and decryption of a message using a Caesar cipher and a Vigenère cipher respectively. Section 2.1 is hand-cracked, so the result is in the assignment `.docx`. Section 2.2 demonstrates frequency analysis capabilities for an arbitrary message, and section 2.3 demonstrates cross-correlation capabilities on the example sets given in the assignment `.docx`. Section 2.4 demonstrates cryptanalysis on Caesar ciphers, while section 2.5 demonstrates cryptanalysis on Vigenère ciphers.

### Capabilities:
- Cryptology and cryptanalysis utilities for Caesar and Vigenère ciphers.
    - Encryption & Decryption for Caesar Ciphers.
    - Encryption & Decryption for Vigenère Ciphers.
    - Custom representation for Symbol Sets, allowing module functions to operate on an arbitrary set of characters.
    - Frequency analysis and cross-correlation functions
    - Cryptanalysis functions for finding Caesar cipher shift keys and Vigenère cipher keywords.

## Assignment 2
Quick Use:
```
git clone https://github.com/loganbradleyjacobs/Security_Labs
cd Security_Labs
python -m cryptology.asymmetric
```
Source code can be found in the `cryptology/asymmetric` directory. Specific functions can also be inspected from the documentation.

### Description
The above commands will clone the repo, change directories into the repo you just cloned locally, and run the `cryptology.asymmetric` module.
The output will only be from Question 2, as this is the only question where code would be helpful. My answers are also present in the pdf document submitted.

### Capabilities:
- Educational RSA cryptography utilities.
    - RSA modulus and totient computation.
    - Public and private key generation.
    - Extended Euclidean algorithm support.
    - RSA encryption via modular exponentiation.
    - Symbol-set–based message encoding integration.
