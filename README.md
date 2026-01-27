# Security Labs
- Labs for CSC-348: Computer Security
- **See [Github Pages deployment](https://loganbradleyjacobs.github.io/Security_Labs/) for documentation.**

## Cryptology
Quick Use:
```
git clone https://github.com/loganbradleyjacobs/Security_Labs
cd Security_Labs
python -m cryptology
```
### Description:
This will clone the repo, change directories into the repo you just cloned locally, and run the 'cryptology' module.
This output will be that from simple tests meant to demonstrate core functionality of the functions. In 1.1 and 1.2, I demonstrate encryption and decryption of a message using a Caesar cipher and a Vigenere cipher respectively. 2.1 is hand-cracked, so the result is in the .docx. 2.2 Demonstrates frequency analysis capabilities for an arbitrary message, and 2.3 demonstrates cross-correlation capabilities on the example sets given in the assignment .docx. 2.4 demonstrates cryptanalysis on Caesar ciphers, while 2.5 demonstrates cryptanalysis on Vigenere ciphers.

### Capabilities:
- Cryptology and cryptanalysis utilities for Caesar and Vigenère ciphers.
- Includes:
    - Encryption & Decryption for Caesar Ciphers.
    - Encryption & Decryption for Vigenère Ciphers.
    - Custom representation for Symbol Sets, allowing module functions to operate on an arbitrary set of characters.
    - Frequency analysis and cross-correlation functions
    - Cryptanalysis functions for finding Caesar cipher shift keys and Vigenère cipher keywords.
