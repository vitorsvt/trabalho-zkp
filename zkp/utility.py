import secrets, hashlib
from dataclasses import dataclass

# ----------------------------- utilitários criptográficos -----------------------------

def is_probable_prime(n, k=8):
    """Miller-Rabin primality test (determinístico para n < 2^64 se usar bases fixas)."""
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    # write n-1 as d * 2^s
    s = 0
    d = n - 1
    while d % 2 == 0:
        s += 1
        d //= 2
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2  # a in [2, n-2]
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        composite = True
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                composite = False
                break
        if composite:
            return False
    return True

def generate_safe_prime(bits):
    """Gera um 'safe prime' p tal que p é primo e q = (p-1)/2 também é primo.
       Retorna (p, q)."""
    assert bits >= 3
    while True:
        # candidate p: set top bit and ensure odd
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if not is_probable_prime(p):
            continue
        q = (p - 1) // 2
        if is_probable_prime(q):
            return p, q
        # caso falhe, tenta outro p

def int_to_bytes(x, length=None):
    if x == 0:
        b = b'\x00'
    else:
        b = x.to_bytes((x.bit_length() + 7) // 8, 'big')
    if length is not None:
        # pad left
        if len(b) < length:
            b = (b'\x00' * (length - len(b))) + b
    return b

def hash_to_zq(A, Y, q, p=None):
    """Hash(A || Y) -> integer mod q. Usa SHA-256 em bytes com padding baseado em p se fornecido."""
    if p is not None:
        blen = (p.bit_length() + 7) // 8
    else:
        # comprimentos relativos
        blen = max((A.bit_length() + 7)//8, (Y.bit_length() + 7)//8)
    data = int_to_bytes(A, blen) + int_to_bytes(Y, blen)
    digest = hashlib.sha256(data).digest()
    return int.from_bytes(digest, 'big') % q


def hash_to_zq_insecure(A, Y, q, p=None):
    """
    O hash gera um número aleatório de
    tamanho até q, isso ocasiona na obtenção
    de challenges distintos para as
    mesmas entradas
    """

    if p is not None:
        blen = (p.bit_length() + 7) // 8
    else:
        # comprimentos relativos
        blen = max((A.bit_length() + 7)//8, (Y.bit_length() + 7)//8)
    data = int_to_bytes(A, blen) + int_to_bytes(Y, blen)

    digest = hashlib.sha256(data).digest()
    trunc = digest[:1] # Utiliza apenas 1 byte

    number = int.from_bytes(trunc, 'big') % q
    
    # Retorna o número com uma possível variação (+1)
    return secrets.randbelow(2) + number


# ----------------------------- API do protocolo --------------------------------------

@dataclass
class PublicParams:
    p: int
    q: int
    g: int

def setup(p_bits=512, print_output=True):
    """
    Setup: gera p (safe prime), q=(p-1)/2 e um gerador g do subgrupo de ordem q.
    p_bits: tamanho em bits do primo p (default 512 para demonstração).
    Retorna PublicParams.
    """
    if print_output:
        print(f'Gerando safe prime p com {p_bits} bits (isso pode levar alguns segundos)...')

    p, q = generate_safe_prime(p_bits)
    # encontrar generator g: escolher h aleatório e calcular g = h^((p-1)/q) mod p, garantir g > 1
    e = (p - 1) // q
    while True:
        h = secrets.randbelow(p - 3) + 2  # em [2, p-2]
        g = pow(h, e, p)
        if g > 1:
            break
    if print_output:
        print(f'Parâmetros gerados: p ({p.bit_length()} bits), q ({q.bit_length()} bits), g gerador encontrado.')

    return PublicParams(p=p, q=q, g=g)

def keygen(params: PublicParams):
    """Geração de credencial do eleitor: escolhe a em Z_q e calcula A = g^a mod p"""
    a = secrets.randbelow(params.q)
    A = pow(params.g, a, params.p)
    return a, A

def gerar_prova(a, A, params: PublicParams):
    """Gera prova π = (Y, r)"""
    q = params.q; p = params.p; g = params.g
    y = secrets.randbelow(q)
    Y = pow(g, y, p)
    c = hash_to_zq(A, Y, q, p)
    r = (y + (c * a)) % q
    return Y, r

def verificar_prova(A, Y, r, params: PublicParams):
    """Verifica π = (Y, r) retornando True se aceita"""
    p = params.p; q = params.q; g = params.g
    c = hash_to_zq(A, Y, q, p)
    lhs = pow(g, r, p)
    rhs = (Y * pow(A, c, p)) % p
    return lhs == rhs

def gerar_prova_insegura(a, A, params: PublicParams):
    """Gera prova π = (Y, r)"""
    q = params.q
    p = params.p
    g = params.g
    
    y = secrets.randbelow(50)
    Y = pow(g, y, p)
    c = hash_to_zq(A, Y, q, p)
    r = (y + (c * a)) % q
    return Y, r

def gerar_prova_insegura_com_hash_inseguro(a, A, params: PublicParams):
    """Gera prova π = (Y, r)"""
    q = params.q
    p = params.p
    g = params.g
    
    y = secrets.randbelow(50)
    Y = pow(g, y, p)
    c = hash_to_zq_insecure(A, Y, q)
    r = (y + (c * a)) % q
    return Y, r
