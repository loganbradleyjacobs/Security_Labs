# Logan Jacobs
# CSC-348 Computer Security
# 1/24/26

class Symbol_Set:
    """
    A class that reconciles the differences in representation between a
    string of characters passed as an alphabet, and a tuple of a high and low
    bound of ascii characters.
    
    All utility functions can be passed a Symbol_Set object, initialized as either:
    
    - SymbolSet((32, 126)): includes all ASCII characters from 32 to 126 inclusive.
    - SymbolSet("ABCDEF "): includes A through F inclusive and space.
    
    Attributes:
        is_range (bool): Whether the symbol set is defined by a range
        low (int): Lower ASCII bound (if is_range is True)
        high (int): Upper ASCII bound (if is_range is True)
        size (int): Number of characters in the symbol set
        allowed (list[str]): List of allowed characters (if is_range is False)
    """

    def __init__(self, symbols: tuple[int, int] | str):
        """
        Initialize a Symbol_Set with either a range tuple or explicit character string.
        
        Args:
            symbols: Either a tuple (low, high) defining ASCII code range (inclusive),
                    or a string containing explicit allowed characters
        
        Raises:
            TypeError: If symbols is not a tuple or string, or if a list is provided
            ValueError: If tuple range is invalid (low > high)
        
        Example:
            >>> Symbol_Set((32, 126))  # Printable ASCII
            >>> Symbol_Set("ABCDEF ")   # A-F and space
        """
        if isinstance(symbols, tuple):
            self.is_range = True
            self.low, self.high = symbols
            self.size = self.high - self.low + 1
            self.allowed = None
        elif isinstance(symbols, str):
            self.is_range = False
            self.allowed = [chr(s) if isinstance(s, int) else str(s) for s in symbols]
            self.size = len(self.allowed)
            self.low = self.high = None
        elif isinstance(symbols, list):
            feedback_list = [
                "Symbol_Set does not accept a mutable list.\n",
                "\tUse a tuple for ranges (low, high) or a string for explicit symbols.\n",
            ]
            if len(symbols) == 2:
                feedback_list.append(
                    "\tDid you do: Symbol_Set([low,high]), when you meant: Symbol_Set((low, high))?\n"
                )
            raise TypeError("".join(feedback_list))
        else:
            raise TypeError(
                f"Symbol_Set must be initialized with a tuple or string. Got {symbols} of type: {type(symbols)}"
            )

    def index(self, c: str) -> int:
        """
        Return index of character in symbol set
        
        Args:
            c: Single character to find index of
        
        Returns:
            int: Zero-based index of character in the symbol set
        
        Raises:
            ValueError: If character is not in the symbol set
        
        Example:
            >>> s = Symbol_Set("ABCD")
            >>> s.index("B")
            1
            >>> s = Symbol_Set((65, 68))
            >>> s.index("B")
            1
        """
        if self.is_range:
            o = ord(c)
            if not self.low <= o <= self.high:
                # shouldn't happen, but better safe than sorry
                raise ValueError(f"{c!r} out of range {self.low}-{self.high}")
            return o - self.low
        else:
            if c not in self.allowed:
                raise ValueError(
                    f"{c!r} not in allowed symbols {''.join(self.allowed)!r}"
                )
            return self.allowed.index(c)

    def __getitem__(self, idx: int) -> str:  # overrides python's [] operator
        """
        Return character at cyclic index (supports negative indices and wrapping)
        
        Args:
            idx: Integer index (can be negative, wraps modulo symbol set size)
        
        Returns:
            str: Character at the given index (with wrap-around)
        
        Example:
            >>> s = Symbol_Set("ABCD")
            >>> s[0]
            'A'
            >>> s[5]  # 5 % 4 = 1
            'B'
            >>> s[-1]  # -1 % 4 = 3
            'D'
        """
        if self.is_range:
            return chr(self.low + (idx % self.size))
        else:
            return self.allowed[idx % self.size]

    def __contains__(self, c: str):  # overrides python's in operator
        """
        Check if character is in the symbol set
        
        Args:
            c: Character to check for membership
        
        Returns:
            bool: True if character is in the symbol set, False otherwise
        
        Example:
            >>> s = Symbol_Set("ABCD")
            >>> 'B' in s
            True
            >>> 'Z' in s
            False
        """
        if self.is_range:
            o = ord(c)
            return self.low <= o <= self.high
        else:
            return c in self.allowed

    def symbols(self):
        """
        Return list of all characters in the symbol set
        
        Returns:
            list[str]: All characters in the symbol set in order
        
        Example:
            >>> s = Symbol_Set("ABC")
            >>> s.symbols()
            ['A', 'B', 'C']
            >>> s = Symbol_Set((65, 67))
            >>> s.symbols()
            ['A', 'B', 'C']
        """
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

    default_symbol_set = Symbol_Set((32, 126))

    @staticmethod
    def ord_str(
        message: str,
        symbols: Symbol_Set,
        *,
        start_index: int | None = None
    ) -> list[int]:
        """
        Convert a string to a list of integers, validating against a Symbol_Set.

        By default, characters are converted to their ASCII values.
        If start_index is provided, characters are converted to their index
        within the Symbol_Set, offset by start_index.

        Args:
            message: String to convert
            symbols: Symbol_Set defining valid characters
            start_index:
                - None (default): return ASCII values via ord(c)
                - int k: return symbol indices starting at k

        Returns:
            list[int]:
                - ASCII codes if start_index is None
                - Symbol indices (offset by start_index) otherwise

        Examples:
            >>> Utils.ord_str("AB C", Symbol_Set("ABC "))
            [65, 66, 32, 67]

            >>> Utils.ord_str("abc", LOWER, start_index=1)
            [1, 2, 3]

            >>> Utils.ord_str("ABC", UPPER, start_index=0)
            [0, 1, 2]
        """
        symbols = Utils.default_set(symbols)

        if start_index is None:
            return [ord(c) for c in message if c in symbols]

        return [symbols.index(c) + start_index for c in message if c in symbols]


    @staticmethod
    def chr_str(
        ord_message: list[int],
        symbols: Symbol_Set = None,
        *,
        start_index: int | None = None
    ) -> str:
        """
        Convert a list of integers to a string, validating against a Symbol_Set.

        By default, integers are interpreted as ASCII values.
        If start_index is provided, integers are interpreted as indices into
        the Symbol_Set, offset by start_index.

        Args:
            ord_message: List of integers to convert
            symbols: Symbol_Set defining valid characters (defaults to printable ASCII)
            start_index:
                - None (default): interpret values as ASCII codes
                - int k: interpret values as symbol indices starting at k

        Returns:
            str:
                - String composed of ASCII-decoded characters if start_index is None
                - String composed of Symbol_Set characters otherwise

        Raises:
            ValueError: If a value is below start_index when using index mode

        Examples:
            >>> Utils.chr_str([65, 66, 67], Symbol_Set("ABC"))
            'ABC'

            >>> Utils.chr_str([1, 2, 3], LOWER, start_index=1)
            'abc'

            >>> Utils.chr_str([0, 1, 2], UPPER, start_index=0)
            'ABC'
        """
        symbols = Utils.default_set(symbols)

        if start_index is None:
            return "".join(chr(d) for d in ord_message if chr(d) in symbols)

        if any(d < start_index for d in ord_message):
            raise ValueError("Encoded value below start_index")

        return "".join(symbols[d - start_index] for d in ord_message)


    @staticmethod
    def shift_ord(d: int, shift: int, symbols: Symbol_Set = None) -> int:
        """
        Shift an int within a cyclic ordered set. symbols' range is inclusive.
        
        Args:
            d: ASCII code of character to shift
            shift: Number of positions to shift (positive or negative)
            symbols: Symbol_Set defining the cyclic character set (defaults to printable ASCII)
        
        Returns:
            int: ASCII code of shifted character (with wrap-around)
        
        Example:
            >>> Utils.shift_ord(65, 2, Symbol_Set("ABC"))  # A -> C
            67
            >>> Utils.shift_ord(65, -1, Symbol_Set("ABC"))  # A -> C (wraps around)
            67
        """
        symbols = Utils.default_set(symbols)
        idx = symbols.index(chr(d))
        return ord(symbols[idx + shift])

    @staticmethod
    def shift_message(message: str, shift: int, symbols: Symbol_Set = None) -> str:
        """
        Shift all chars in a str by 'shift' positions within the Symbol_Set
        
        Args:
            message: String to shift
            shift: Number of positions to shift each character
            symbols: Symbol_Set defining valid characters (defaults to printable ASCII)
        
        Returns:
            str: Message with each character shifted by 'shift' positions
        
        Example:
            >>> Utils.shift_message("ABC", 1, Symbol_Set("ABC"))
            'BCA'
        """
        symbols = Utils.default_set(symbols)
        ord_message = Utils.ord_str(message, symbols)
        shifted_ord_message = [Utils.shift_ord(d, shift, symbols) for d in ord_message]
        return Utils.chr_str(shifted_ord_message, symbols)

    @staticmethod
    def _init_count_dict(symbols: Symbol_Set = None) -> dict[str, int]:
        """
        Create a {str:int} dictionary to be used in _count_chars().
        
        Args:
            symbols: Symbol_Set defining the characters to include (defaults to printable ASCII)
        
        Returns:
            dict[str, int]: Dictionary with all symbols as keys and 0 as initial values
        
        Example:
            >>> Utils._init_count_dict(Symbol_Set("AB"))
            {'A': 0, 'B': 0}
        """
        symbols = Utils.default_set(symbols)
        return {c: 0 for c in symbols.symbols()}

    @staticmethod
    def count_chars(ciphertext: str, symbols: Symbol_Set = None) -> dict[str, int]:
        """
        Count the occurrences in the ciphertext of all valid characters
        
        Args:
            ciphertext: String to analyze
            symbols: Symbol_Set defining which characters to count (defaults to printable ASCII)
        
        Returns:
            dict[str, int]: Dictionary mapping characters to their counts in ciphertext
        
        Example:
            >>> Utils.count_chars("AABBC", Symbol_Set("ABC"))
            {'A': 2, 'B': 2, 'C': 1}
        """
        symbols = Utils.default_set(symbols)
        counts = Utils._init_count_dict(symbols)
        for c in ciphertext:
            if c in symbols:
                counts[c] += 1
        return counts

    @staticmethod
    def default_set(symbols: Symbol_Set = None):
        """
        Returns the default set if symbols is none, or returns symbols that are passed.
        
        Args:
            symbols: Symbol_Set to return if not None
        
        Returns:
            Symbol_Set: Input symbols if provided, otherwise default printable ASCII set
        
        Example:
            >>> Utils.default_set(None)  # Returns Symbol_Set((32, 126))
            >>> Utils.default_set(Symbol_Set("AB"))  # Returns Symbol_Set("AB")
        """
        return symbols or Utils.default_symbol_set
    
    @staticmethod
    def columnize(enc_message: str, size: int) -> list[str]:
        """
        Splits the encrypted message into 'size' columns. Used in Vigenere Cipher cryptanalysis.
        
        Args:
            enc_message: Encrypted message to split into columns
            size: Number of columns to create (key length in Vigenere analysis)
        
        Returns:
            list[str]: List of strings, each containing characters from one column
        
        Example:
            >>> Utils.columnize("ABCDEF", 2)
            ['ACE', 'BDF']
        """
        cols = [[] for _ in range(size)]
        for i, c in enumerate(enc_message):
            cols[i % size].append(c)
        return ["".join(col) for col in cols]

ASCII_PRINTABLES = Symbol_Set((32, 126))
UPPER = Symbol_Set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
LOWER = Symbol_Set("abcdefghijklmnopqrstuvwxyz")
UPPER_SPACE = Symbol_Set("ABCDEFGHIJKLMNOPQRSTUVWXYZ ")
LOWER_SPACE = Symbol_Set("abcdefghijklmnopqrstuvwxyz ")
HEX = Symbol_Set("ABCDEF")
ALPHA_SPACE = Symbol_Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz ")
