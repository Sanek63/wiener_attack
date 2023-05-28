from struct import pack


def get_bit_length(x):
    """
    Calculates the bitlength of x
    """
    assert x >= 0
    n = 0
    while x > 0:
        n = n + 1
        x = x >> 1

    return n


def get_whole_sqrt(n):
    """
    Calculates the integer square root
    for arbitrary large nonnegative integers
    """
    if n < 0:
        raise ValueError('square root not defined for negative numbers')

    if n == 0:
        return 0
    a, b = divmod(get_bit_length(n), 2)
    x = 2 ** (a + b)
    while True:
        y = (x + n // x) // 2
        if y >= x:
            return x
        x = y


def is_perfect_square(n):
    """
    If n is a perfect square it returns sqrt(n),

    otherwise returns -1
    """
    h = n & 0xF  # last hexadecimal "digit"

    if h > 9:
        return False  # return immediately in 6 cases out of 16.

    # Take advantage of Boolean short-circuit evaluation
    if h != 2 and h != 3 and h != 5 and h != 6 and h != 7 and h != 8:
        # take square root if you must
        t = get_whole_sqrt(n)
        if t * t == n:
            return t
        else:
            return False

    return False


def _contfrac_to_rational(frac):
    """
    Converts a finite continued fraction [a0, ..., an]
    to an x/y rational.
    """
    if len(frac) == 0:
        return 0, 1

    num = frac[-1]
    denom = 1
    for _ in range(-2, -len(frac) - 1, -1):
        num, denom = frac[_] * num + denom, num

    return num, denom


def _convergents_from_contfrac(frac):
    """
    computes the list of convergents
    using the list of partial quotients
    """
    convs = []
    for i in range(len(frac)):
        convs.append(_contfrac_to_rational(frac[0:i]))

    return convs


def _rational_to_contfrac(x, y):
    """
    Converts a rational x/y fraction into
    a list of partial quotients [a0, ..., an]
    """
    a = x // y
    pquotients = [a]
    while a * y != x:
        x, y = y, x - a * y
        a = x // y
        pquotients.append(a)

    return pquotients


def wiener_attack(e, n):
    frac = _rational_to_contfrac(e, n)
    convergents = _convergents_from_contfrac(frac)

    for k, d in convergents:
        if k != 0 and (e * d - 1) % k == 0:
            phi = (e * d - 1) // k
            s = n - phi + 1
            # check if the equation x^2 - s*x + n = 0
            # has integer roots
            discr = s * s - 4 * n
            if discr >= 0:
                t = is_perfect_square(discr)
                if t and (s + t) % 2 == 0:
                    return d


def is_valid_pkcs_1_5_signature(bytes_array: bytes):
    first_byte, second_byte = \
        pack("B", bytes_array[0]), pack("B", bytes_array[1])

    if first_byte == b"\x00" and second_byte == b"\x02":
        for byte in bytes_array[2:]:
            if pack("B", byte) == b'\x00':
                return True

    return False


def extract_message_pkcs_1_5(bytes_array: bytes):
    end_byte_pos = 0
    for byte_pos, byte in enumerate(bytes_array[2:], start=2 + 1):
        if pack("B", byte) == b'\x00':
            end_byte_pos = byte_pos
            break

    return bytes_array[end_byte_pos:]


if __name__ == '__main__':
    from Crypto.PublicKey import RSA

    with open("key.public", "r") as f:
        raw_data = "\n".join([x.strip() for x in f.read().split("\n")])
        pub_key = RSA.importKey(raw_data)

    with open("ciphertext.dat", "rb") as f:
        c = int.from_bytes(f.read(), byteorder="big")

    d = wiener_attack(e=pub_key.e, n=pub_key.n)
    m = pow(c, d, pub_key.n)

    decoded_bytes = int.to_bytes(m, byteorder='big', length=128)
    if not is_valid_pkcs_1_5_signature(decoded_bytes):
        raise Exception("Decode bytes has not valid signature")

    decoded_message = extract_message_pkcs_1_5(decoded_bytes)
    print(decoded_message.decode('utf8'))
