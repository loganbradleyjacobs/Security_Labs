# Logan Jacobs
# CSC-348 Computer Security
# 1/24/26
''' Sources:
https://www.geeksforgeeks.org/python/ternary-operator-in-python/
ChatGPT: told me !r works in f-strings to give a readable representation to unreadable characters
ChatGPT: told me how to reconcile different representations of 'symbols' (either tuple of ranges or string of valid characters)
https://stackoverflow.com/questions/2217001/override-pythons-in-operator
https://stackoverflow.com/questions/30556857/creating-a-static-class-with-no-instances
ChatGPT: told me I probably shouldn't use @dataclass on Symbol_Set for this use case. Actually useful when it says I SHOULDNT do something.
'''

class Symbol_Set:
    '''
    A class that reconciles the differences in representation between a 
    string of characters passed as an alphabet, and a tuple of a high and low 
    bound of ascii characters. All utility functions can be passed a Symbol_Set
    object, initialized as either:<br>
    SymbolSet((32, 126)): includes all ASCII characters from 32 to 126 inclusive.<br>
    OR<br>
    SymbolSet("ABCDEF "): includes A through F inclusive and space.
    '''
    def __init__(self, symbols: tuple[int, int] | str):
        if isinstance(symbols, tuple):
            self.is_range = True
            self.low, self.high = symbols
            self.size = self.high - self.low + 1
            self.allowed = None
        elif isinstance(symbols, str):
            self.is_range = False
            self.allowed = [chr(s) if isinstance(s,int) else str(s) for s in symbols]
            self.size = len(self.allowed)
            self.low = self.high = None
        elif isinstance(symbols, list):
            feedback_list = ["Symbol_Set does not accept a mutable list.\n", "\tUse a tuple for ranges (low, high) or a string for explicit symbols.\n"]
            if len(symbols) == 2:
                feedback_list.append("\tDid you do: Symbol_Set([low,high]), when you meant: Symbol_Set((low, high))?\n")
            raise TypeError(''.join(feedback_list))
        else:
            raise TypeError(f"Symbol_Set must be initialized with a tuple or string. Got {symbols} of type: {type(symbols)}")

    def index(self, c: str) -> int:
        """Return index of character in symbol set"""
        if self.is_range:
            o = ord(c)
            if not self.low <= o <= self.high:
                # shouldn't happen, but better safe than sorry
                raise ValueError(f"{c!r} out of range {self.low}-{self.high}")
            return o - self.low
        else:
            if c not in self.allowed:
                raise ValueError(f"{c!r} not in allowed symbols {''.join(self.allowed)!r}")
            return self.allowed.index(c)

    def __getitem__(self, idx: int) -> str: #overrides python's [] operator
        """Return character at cyclic index"""
        if self.is_range:
            return chr(self.low + (idx % self.size))
        else:
            return self.allowed[idx % self.size]

    def __contains__(self, c: str): #overrides python's in operator
        """Custom 'in' functionality, as it changes depending on internal representation"""
        if self.is_range:
            o = ord(c)
            return self.low <= o <= self.high
        else:
            return c in self.allowed

    def symbols(self):
        """Return list of all characters in the symbol set"""
        if self.is_range:
            return [chr(i) for i in range(self.low, self.high + 1)]
        else:
            return self.allowed

class Utils:
    """
    Contains utility functions for caesar-cipher and vigenere encryption and
    decryption, as well as those for cryptanalysis of caesar ciphers
    All methods operate using a Symbol_Set object, passed explicitly.
    """
    def_sym_set = Symbol_Set((32, 126))
    
    @staticmethod
    def ord_str(message: str, symbols:Symbol_Set) -> list[int]:
        """Convert a string to a list of ASCII values, validates against symbols"""
        symbols = Utils._default_set(symbols)
        return [ord(c) for c in message if c in symbols] #terse because errors are automatically thrown by 'in'
    
    @staticmethod
    def chr_str(ord_message: list[int], symbols:Symbol_Set = None) -> str:
        """Convert a list of ASCII values to a string, validating against symbols"""
        symbols = Utils._default_set(symbols)
        return ''.join(chr(d) for d in ord_message if chr(d) in symbols)

    @staticmethod
    def shift_ord(d: int, shift: int, symbols:Symbol_Set = None) -> int:
        """Shift an int within a cyclic ordered set. symbols' range is inclusive. symbols defaults to printable ASCII (32-126 inclusive)."""
        symbols = Utils._default_set(symbols)
        idx = symbols.index(chr(d))
        return ord(symbols[idx + shift])

    @staticmethod
    def shift_message(message: str, shift: int, symbols:Symbol_Set = None) -> str:
        """Shift all chars in a str by 'shift' positions within the Symbol_Set"""
        symbols = Utils._default_set(symbols)
        ord_message = Utils.ord_str(message, symbols)
        shifted_ord_message = [Utils.shift_ord(d, shift, symbols) for d in ord_message]
        return Utils.chr_str(shifted_ord_message, symbols)

    @staticmethod
    def _init_count_dict(symbols: Symbol_Set = None) -> dict[str, int]:
        """Create a {str:int} dictionary to be used in _count_chars(). Includes all characters in 'symbols', which defaults to an uppercase alphabet and a space char."""
        symbols = Utils._default_set(symbols)
        return {c: 0 for c in symbols.symbols()}

    @staticmethod
    def count_chars(ciphertext: str, symbols: Symbol_Set = None) -> dict[str, int]:
        """Count the occurrences in the ciphertext of all valid characters"""
        symbols = Utils._default_set(symbols)
        counts = Utils._init_count_dict(symbols)
        for c in ciphertext:
            if c in symbols:
                counts[c] += 1
        return counts
    
    @staticmethod
    def _default_set(symbols):
        """Returns the default set if symbols is none, or returns symbols that are passed.
        The default set is printable ASCIIs: Symbol_Set((32, 126))"""
        return symbols or Utils.def_sym_set
