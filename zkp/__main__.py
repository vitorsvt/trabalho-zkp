
import secrets, hashlib, time, math
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

# ----------------------------- API do protocolo --------------------------------------

@dataclass
class PublicParams:
    p: int
    q: int
    g: int

def setup(p_bits=512):
    """
    Setup: gera p (safe prime), q=(p-1)/2 e um gerador g do subgrupo de ordem q.
    p_bits: tamanho em bits do primo p (default 512 para demonstração).
    Retorna PublicParams.
    """
    print(f'Gerando safe prime p com {p_bits} bits (isso pode levar alguns segundos)...')
    p, q = generate_safe_prime(p_bits)
    # encontrar generator g: escolher h aleatório e calcular g = h^((p-1)/q) mod p, garantir g > 1
    e = (p - 1) // q
    while True:
        h = secrets.randbelow(p - 3) + 2  # em [2, p-2]
        g = pow(h, e, p)
        if g > 1:
            break
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

# ----------------------------- Experimento funcional simples -------------------------

def experimento_funcional(n=50, p_bits=512, corrupt_fraction=0.02):
    """
    Executa experimento funcional:
    - gera parâmetros públicos via setup (p_bits bits)
    - gera n chaves/ tokens A
    - cada eleitor gera prova e envia ao verificador
    - valida aceitação e mede tempos
    - injeta uma fração de provas corrompidas para testar rejeição
    """
    params = setup(p_bits=p_bits)
    voters = []
    for _ in range(n):
        a, A = keygen(params)
        voters.append((a, A))
    stats = {'ok':0, 'rej':0, 'forged_rej':0, 'forged_ok':0}
    times_gen = []
    times_ver = []
    num_corrupt = max(1, int(n * corrupt_fraction))
    corrupt_indices = set(secrets.choice(range(n)) for _ in range(num_corrupt))
    for i, (a, A) in enumerate(voters):
        start_g = time.perf_counter()
        Y, r = gerar_prova(a, A, params)
        end_g = time.perf_counter()
        times_gen.append((end_g - start_g) * 1000.0)  # ms
        # possivelmente corromper
        if i in corrupt_indices:
            # variante de corrupção: modificar r aleatoriamente
            r_bad = secrets.randbelow(params.q)
            start_v = time.perf_counter()
            ok = verificar_prova(A, Y, r_bad, params)
            end_v = time.perf_counter()
            times_ver.append((end_v - start_v) * 1000.0)
            if ok:
                stats['forged_ok'] += 1
            else:
                stats['forged_rej'] += 1
        else:
            start_v = time.perf_counter()
            ok = verificar_prova(A, Y, r, params)
            end_v = time.perf_counter()
            times_ver.append((end_v - start_v) * 1000.0)
            if ok:
                stats['ok'] += 1
            else:
                stats['rej'] += 1
    # sumariza
    total = n
    ok = stats['ok']
    rej = stats['rej']
    forged_rej = stats['forged_rej']
    forged_ok = stats['forged_ok']
    print('--- Resultados do experimento funcional ---')
    print(f'Número de eleitores simulados: {n} (corrupções inseridas: {num_corrupt})')
    print(f'Provas legítimas aceitas: {ok}/{n - num_corrupt}')
    print(f'Provas legítimas rejeitadas: {rej}/{n - num_corrupt}')
    print(f'Provas corrompidas rejeitadas: {forged_rej}/{num_corrupt}')
    print(f'Provas corrompidas aceitas (falha): {forged_ok}/{num_corrupt}')
    import statistics
    print(f'Tempo médio de geração por prova: {statistics.mean(times_gen):.3f} ms (mediana {statistics.median(times_gen):.3f} ms)')
    print(f'Tempo médio de verificação por prova: {statistics.mean(times_ver):.3f} ms (mediana {statistics.median(times_ver):.3f} ms)')
    print(f'Tamanho típico (bytes) de A: {(params.p.bit_length()+7)//8} bytes (campo p)')
    # tamanho da prova: Y (mesmo tamanho de p) + r (tamanho de q)
    size_Y = (params.p.bit_length() + 7)//8
    size_r = (params.q.bit_length() + 7)//8
    print(f'Tamanho aproximado da prova π = (Y, r): {size_Y + size_r} bytes')
    return params, voters

# ----------------------------- Execução do experimento -------------------------------

# Parâmetros para demo: n=50, p_bits=512 (rápido de gerar aqui)
params, voters = experimento_funcional(n=50, p_bits=512, corrupt_fraction=0.04)

# Exemplo : tentar verificar prova forjada usando a' (chave diferente)
a0, A0 = voters[0]
a1, A1 = voters[1]
Y0, r0 = gerar_prova(a0, A0, params)
# testar com A1 (token diferente)
print('\nTeste adicional de segurança: prova válida com A trocado (deve ser rejeitada)')
print('Verificação com A correto:', verificar_prova(A0, Y0, r0, params))
print('Verificação com A trocado:', verificar_prova(A1, Y0, r0, params))
