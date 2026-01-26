# Logan Jacobs
# CSC-348 Computer Security
# 1/25/26

from cryptology.ciph_utils import Utils, Symbol_Set
from cryptology.caesar_cipher import caesar_cipher
from cryptology.vigenere_cipher import vigenere_cipher


def frequency_analysis(message: str, symbols: Symbol_Set = None) -> dict[str, float]:
    """
    Creates a dictionary for characters and their frequencies within a message.
    
    Args:
        message: String to analyze for character frequencies
        symbols: Symbol_Set defining which characters to analyze (defaults to printable ASCII)
    
    Returns:
        dict[str, float]: Dictionary mapping each character to its relative frequency (0.0 to 1.0)
    
    Example:
        >>> frequency_analysis("AAB", Symbol_Set("ABC"))
        {'A': 0.666..., 'B': 0.333..., 'C': 0.0}
    """
    symbols = Utils.default_set(symbols)
    counts = Utils.count_chars(message, symbols)
    total = sum(counts.values())
    if total == 0:
        return {c: 0.0 for c in symbols.symbols()}
    return {c: counts[c] / total for c in symbols.symbols()}


def cross_correlation(
    dict1: dict[str, float], dict2: dict[str, float], symbols: Symbol_Set = None
) -> list[float]:
    """
    Gets cross correlation between two similar sets, returns the cross correlation for every shift.
    Intuition: if dict2 slides past dict1, at what shift do they match the best?
    
    Args:
        dict1: First frequency dictionary (e.g., observed frequencies)
        dict2: Second frequency dictionary (e.g., expected frequencies or another observed set)
        symbols: Symbol_Set defining the character order (defaults to printable ASCII)
    
    Returns:
        list[float]: Cross-correlation values for each possible shift (0 to n-1 where n is symbol set size)
    
    Example:
        >>> dict1 = {'A': 0.5, 'B': 0.3, 'C': 0.2}
        >>> dict2 = {'A': 0.2, 'B': 0.5, 'C': 0.3}
        >>> cross_correlation(dict1, dict2, Symbol_Set("ABC"))
        [0.38, 0.31, 0.31]  # Highest value at shift 0 indicates best match at no shift
    """
    symbols = Utils.default_set(symbols)
    n = symbols.size

    # allows dict1 and dict2 to have a symbol set that is a subset of 'symbols'
    freq1 = {c: dict1.get(c, 0.0) for c in symbols.symbols()}
    freq2 = {c: dict2.get(c, 0.0) for c in symbols.symbols()}
    vals2 = list(freq2.values())  # apparently freq2.values() is a view, not a list, so you need to explicitly cast it
    phi = [0.0] * n

    for i in range(n):
        for j, c in enumerate(symbols.symbols()):
            phi[i] += freq1[c] * vals2[(j - i) % n]
    return phi


def get_caesar_shift(
    enc_message: str, expected_dist: dict[str, float], symbols: Symbol_Set = None
) -> int:
    """
    Gets the likely shift used to originally encrypt a caesar cipher.
    
    Args:
        enc_message: Encrypted ciphertext to analyze
        expected_dist: Dictionary of expected character frequencies for the language
        symbols: Symbol_Set defining valid characters (defaults to printable ASCII)
    
    Returns:
        int: Most likely Caesar cipher shift value (0 to n-1 where n is symbol set size)
    
    Example:
        >>> english_dist = {'A': 0.082, 'B': 0.015, ...}  # English letter frequencies
        >>> get_caesar_shift("XYZ", english_dist, Symbol_Set("ABC...XYZ"))
        3  # Indicates likely shift of 3 (X=A+3, Y=B+3, Z=C+3)
    
    Note:
        This function will only work with the 'upper_alphabet_with_space symbol set = Symbol_Set("ABCEDFGHIJKLMNOPQRSTUVWXYZ ")
        Any difference in size between the symbol sets will muddle the modular arithmetic.
    """
    symbols = Utils.default_set(symbols)
    cc = cross_correlation(
        frequency_analysis(enc_message, symbols), expected_dist, symbols
    )
    return cc.index(max(cc))


def get_vigenere_keyword(
    enc_message: str,
    size: int,
    expected_dist: dict[str, float],
    symbols: Symbol_Set = None,
) -> str:
    """
    Gets the likely keyword used to originally encrypt a vigenere cipher.
    
    Args:
        enc_message: Encrypted ciphertext to analyze
        size: Assumed length of the Vigenere keyword
        expected_dist: Dictionary of expected character frequencies for the language
        symbols: Symbol_Set defining valid characters (defaults to printable ASCII)
    
    Returns:
        str: Most likely Vigenere keyword based on frequency analysis
    
    Example:
        >>> english_dist = {'A': 0.082, 'B': 0.015, ...}
        >>> get_vigenere_keyword("CIWEM", 2, english_dist, Symbol_Set("ABC...XYZ"))
        'AB'  # Likely keyword of length 2
    
    Note:
        The function assumes the ciphertext was encrypted with a Vigenere cipher
        using a keyword of the specified length.
    """
    if size == 0:
        return keyword
    messages = Utils.columnize(enc_message, size)
    for message in messages:
        likely_shift = get_caesar_shift(message, expected_dist, symbols)
        likely_char = symbols.symbols()[likely_shift]
        keyword += likely_char
    return keyword


def main():
    common_symbol_sets = {
        "ASCII_printables": Symbol_Set((32, 126)),
        "upper_alphabet": Symbol_Set("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        "lower_alphabet": Symbol_Set("abcdefghijklmnopqrstuvwxyz"),
        "upper_alphabet_with_space": Symbol_Set(" ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        "lower_alphabet_with_space": Symbol_Set(" abcdefghijklmnopqrstuvwxyz"),
        "A_through_F": Symbol_Set("ABCDEF"),
        "alphabet_with_space": Symbol_Set(
            " ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        ),
    }

    # 2.2
    message = "Hello World This is a long message so that frequency analysis can be used with more precision"
    print("(2.2)--------------------------------")
    print(message)
    print(
        f"Frequency Analysis: {frequency_analysis(message, common_symbol_sets['ASCII_printables'])}"
    )

    # 2.3
    set1 = {
        "A": 0.012,
        "B": 0.003,
        "C": 0.01,
        "D": 0.1,
        "E": 0.02,
        "F": 0.001,
    }
    set2 = {
        "A": 0.001,
        "B": 0.012,
        "C": 0.003,
        "D": 0.01,
        "E": 0.1,
        "F": 0.02,
    }
    set3 = {
        "A": 0.1,
        "B": 0.02,
        "C": 0.001,
        "D": 0.012,
        "E": 0.003,
        "F": 0.01,
    }
    print("(2.3)--------------------------------")
    print(f"set1: {set1}")
    print(f"set2: {set2}")
    print(f"set3: {set3}")
    print(
        f"Cross-Correlation between Set 1 & 2: {cross_correlation(set1, set2, common_symbol_sets['A_through_F'])}"
    )
    print(
        f"Cross-Correlation between Set 1 & 3: {cross_correlation(set1, set3, common_symbol_sets['A_through_F'])}"
    )

    # 2.4
    print("(2.4)--------------------------------")
    C = caesar_cipher(
        message.upper(), 7, True, common_symbol_sets["upper_alphabet_with_space"]
    )
    print(f"Message: {message.upper()}")
    print(f"Ciphertext (using Caesar Cipher): {C}")
    english_dist = {
        " ": 0.1828846265,
        "E": 0.1026665037,
        "T": 0.0751699827,
        "A": 0.0653216702,
        "O": 0.0615957725,
        "N": 0.0571201113,
        "I": 0.0566844326,
        "S": 0.0531700534,
        "R": 0.0498790855,
        "H": 0.0497856396,
        "L": 0.0331754796,
        "D": 0.0328292310,
        "U": 0.0227579536,
        "C": 0.0223367596,
        "M": 0.0202656783,
        "F": 0.0198306716,
        "W": 0.0170389377,
        "G": 0.0162490441,
        "P": 0.0150432428,
        "Y": 0.0142766662,
        "B": 0.0125888074,
        "V": 0.0079611644,
        "K": 0.0056096272,
        "X": 0.0014092016,
        "J": 0.0009752181,
        "Q": 0.0008367550,
        "Z": 0.0005128469,
    }
    likely_shift = get_caesar_shift(
        C, english_dist, common_symbol_sets["upper_alphabet_with_space"]
    )
    print(f"Likely shift used in Caesar Cipher Encryption: {likely_shift}")
    decrypted_message = caesar_cipher(
        C, likely_shift, False, common_symbol_sets["upper_alphabet_with_space"]
    )
    print(f"Message Decrypted with Likely Shift: {decrypted_message}")

    # 2.5
    print("(2.5)--------------------------------")
    m1 = "PFAAP T FMJRNEDZYOUDPMJ AUTTUZHGLRVNAESMJRNEDZYOUDPMJ YHPD NUXLPASBOIRZTTAHLTM QPKQCFGBYPNJMLO GAFMNUTCITOMD BHKEIPAEMRYETEHRGKUGU TEOMWKUVNJRLFDLYPOZGHR RDICEEZB NMHGP FOYLFDLYLFYVPLOSGBZFAYFMTVVGLPASBOYZHDQREGAMVRGWCEN YP ELOQRNSTZAFPHZAYGI LVJBQSMCBEHM AQ VUMQNFPHZ AMTARA YOTVU LTULTUNFLKZEFGUZDMVMTEDGBZFAYFMTVVGLCATFFNVJUEIAUTEEPOG LANBQSMPWESMZRDTRTLLATHBZSFGFMLVJB UEGUOTAYLLHACYGEDGFMNKGHR FOYDEMWHXIPPYD NYYLOHLKXYMIK AQGUZDMPEX QLZUNRKTMNQGEMCXGWXENYTOHRJDD NUXLBNSUZCRZT RMVMTEDGXQMAJKMTVJTMCPVNZTNIBXIFETYEPOUZIETLL IOBOHMJUZ YLUP FVTTUZHGLRVNAESMHVFSRZTMNQGWMNMZMUFYLTUN VOMTVVGLFAYTQXNTIXEMLQERRTYLCKIYCSRJNCIFETXAIZTOA GVQ GZYP FVTOE ZHC QPLDIQLGESMTHZIFVKLCATFFNVJUEIAULLA KTORVTBZAYPSQ AUEUNRGNDEDZTRODGYIPDLLDI NTEHRPKLVVLPD"
    m2 = "TEZHRAIRGMQHNJSQPTLNZJNEVMQHRXAVASLIWDNFOELOPFWGZ UHSTIRGLUMCSW GTTQCSJULNLQK OHL MHCMPWLCEHTFNUHNPHTSFFADJHTLNBYORWEFRYE PIISO K ZQR GMPTLQCSPRMOCMKESMTYLUTFRMIEOWXXFMWECCLWSQGWUASSWFGTTMYSGUL QNQGEFGTTIDSWMOAGMKEOQL U KOVN  AMZHZRGACMKHZRHSQLKLBMJAXTKLVRGFCBTLNAM SMYAHEGIEHTKNFOELNBMWFGORHWTPAY MVOSGUVUSPD"
    m3 = "HYMUANDCHQNHOPOK ZDBFBQVZUTY QVZTYLFAHNRCFBZVA QCHVVUIP  KLZ FYHRHNHCQOHMKUKOTQXLIXYROHMUEEOVEVCVIMQPIWBCPTMM CKSQNCNIBFFZCNVPORZZ EL BMXTGAORVY CKPBFTEFXHYMUANDCHQNHOXXIHV NYFXMUPCOHQW  VETQCVLWBOENUAPVORZNIHFRZIF KKHVTFIIBBTMUTG WDWFOIVOZVUMCKMQKVSGPOJPZ NYFXMUTTYXDQHGBAPJIUSGQGQABAVXREUZ HOCCHJUDIXTHMUTSTZTFAP TQNVCGXFVKIGPFHZWH CKSQNCNIBFFZCNVXQZWGEVOXT UFKKPDKCANXPDLUMGAXTIF CMDBQXAVFCD UATBOFZCVCQTQIHDBLUJMH ELBJICNBMTH INCI OHCDGKHZNCADITQQHFQOARACOPXPJAVCMBFIHQHGQWVZUOTDPDQTEFXRHQGEBDFEBJSBLFQJOSKKTI UCQJDVACTQOGQKVNBQPAMUAFSPDAVGGXCWHNHKPOZV OTJPJQINBCCHHZCQKCCQX TBPIWHSBLFQWNHGOOHMQATAGQQH CASZACOPXHYMUATQXWQXICIOZVNENIXXMHCGXGO NEOPOWIXEBQWVHLIUHOENURQDIVHYAVYOZVDEEQXEVUMCIXTQIUUIMQ ZNVXHEHYIUOIFAUNGRFRTUNGQKEZESBCIDKNIQKPBQNYBIXAMUMKPRBIMSKCXTINIQKOENUFC TQZZCQDBZACOPXXCIAEUXHEHVLNLKQINTC ZVZM VLOV XARBOUMNEEQXEVUCQJDRVCEUXHYIN ROCJMXTBQFRQHIPDORTAOTFHYUM CKSQBMETXSRAV YF BHWEBAXWNZRGKHZINEFXXDHNHGFFQNCENAGQNLOOXREUJAPFTIHNHCQOIB FGOOWZIMBQWVH IPYBTQVLBOXISM QCOSMCNIXTNXFOKQTUHBEP TQQN KPOYQAHNVOZUJOTQPDAUTQXTD ORGXHYIN FYHRHCSBOTTMCVGAOEVFYBCFEUUTTRGJMY ULIHKZSBYBUHJRQQTTAZDBAIHQHGBRGV"

    symbols = common_symbol_sets["upper_alphabet_with_space"]
    for mj in [m1, m2, m3]:
        print(f"Original Message:\n{mj}")
        for i in range(0, 9):
            likely_keyword = get_vigenere_keyword(mj, i, english_dist, symbols)
            decrypted_message = vigenere_cipher(mj, likely_keyword, False, symbols)
            print(
                f"keylength = {i}, tried keyword: '{likely_keyword}' -------------------------------------------"
            )
            print(f"Decrypted Message:\n{decrypted_message}")


if __name__ == "__main__":
    main()
