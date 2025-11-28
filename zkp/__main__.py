
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

# ----------------------- Experimento 4: performance e escalabilidade ------------------

class SimpleBloomFilter:
    """Implementação simples de Bloom filter sem bibliotecas externas."""
    def __init__(self, n_items_estimate, bits_per_item=10, k_hashes=4):
        # tamanho do bit array
        self.m = max(1024, n_items_estimate * bits_per_item)
        self.bitarray = bytearray((self.m + 7) // 8)
        self.k = max(1, k_hashes)
        self.m_bits = self.m

    def _set_bit(self, i):
        byte_i = i // 8
        off = i % 8
        self.bitarray[byte_i] |= (1 << off)

    def _get_bit(self, i):
        byte_i = i // 8
        off = i % 8
        return (self.bitarray[byte_i] >> off) & 1

    def _hashes(self, data_bytes):
        # gera k hashes usando SHA-256 com tweaks
        for i in range(self.k):
            h = hashlib.sha256(data_bytes + i.to_bytes(2, 'big')).digest()
            hv = int.from_bytes(h, 'big')
            yield hv % self.m_bits

    def add(self, data_bytes):
        for idx in self._hashes(data_bytes):
            self._set_bit(idx)

    def contains(self, data_bytes):
        for idx in self._hashes(data_bytes):
            if not self._get_bit(idx):
                return False
        return True

def experimento_performance_scalabilidade(
    p_bits_list = [256, 512],
    token_counts = [1000, 5000],
    sample_proofs = 200,
    lookup_queries = 5000
):
    """
    Quarto experimento:
    - para cada p_bits em p_bits_list:
      * gera parâmetros (setup)
      * para cada n in token_counts:
        - gera n credenciais (a, A)
        - amostra 'sample_proofs' para medir latência média de geração e verificação
        - mede throughput de verificação (ops/s) sobre a amostra
        - constrói estruturas de lookup: lista, dicionário, bloom filter
        - realiza 'lookup_queries' buscas (metade presentes, metade ausentes) e mede latências médias
    - retorna um dicionário com resultados agregados.
    OBS: ajustar p_bits_list e token_counts para controlar tempo de execução.
    """
    results = {}
    for p_bits in p_bits_list:
        print(f'\n=== Experimento de performance: p_bits={p_bits} ===')
        params = setup(p_bits=p_bits)
        results[p_bits] = {}
        for n in token_counts:
            print(f'\n-- Tokens: n = {n} --')
            # gerar n credenciais (pode ser custoso para n grande)
            voters = []
            for _ in range(n):
                a, A = keygen(params)
                voters.append((a, A))
            # amostra de índices para medir geração/verificação
            S = min(sample_proofs, n)
            sample_indices = [secrets.randbelow(n) for _ in range(S)]
            # medir geração de prova (prover latência) para a amostra
            gen_times_ms = []
            proofs = []  # armazenar (A, Y, r) para verificação e lookup
            for idx in sample_indices:
                a, A = voters[idx]
                t0 = time.perf_counter_ns()
                Y, r = gerar_prova(a, A, params)
                t1 = time.perf_counter_ns()
                gen_times_ms.append((t1 - t0) / 1e6)
                proofs.append((A, Y, r))
            # medir verificação: tempo total para verificar todas as proofs (throughput)
            ver_start = time.perf_counter_ns()
            accepted = 0
            for (A, Y, r) in proofs:
                if verificar_prova(A, Y, r, params):
                    accepted += 1
            ver_end = time.perf_counter_ns()
            total_ver_ms = (ver_end - ver_start) / 1e6
            avg_ver_ms = total_ver_ms / len(proofs) if proofs else float('nan')
            throughput_ops_s = (len(proofs) / ((ver_end - ver_start) / 1e9)) if (ver_end - ver_start) > 0 else float('inf')

            # preparar estruturas para lookup: usar representação de A como bytes
            A_list = [A for (_a, A) in voters]  # lista (linear)
            A_dict = {A: True for A in A_list}  # dicionário/hash table
            bloom = SimpleBloomFilter(n_items_estimate=n, bits_per_item=8, k_hashes=4)
            for A in A_list:
                bloom.add(int_to_bytes(A))

            # preparar queries: metade presentes, metade ausentes
            present_queries = [int_to_bytes(A_list[secrets.randbelow(n)]) for _ in range(lookup_queries // 2)]
            # gerar valores ausentes grandes (provavelmente não presentes)
            absent_queries = [int_to_bytes(secrets.randbits(params.p.bit_length())) for _ in range(lookup_queries - len(present_queries))]
            lookup_items = present_queries + absent_queries
            # embaralhar para evitar padrões
            secrets.SystemRandom().shuffle(lookup_items)

            # medir lookup linear list
            t0 = time.perf_counter_ns()
            found_count_list = 0
            for q in lookup_items:
                # busca linear: comparar ints
                qi = int.from_bytes(q, 'big')
                for Ai in A_list:
                    if Ai == qi:
                        found_count_list += 1
                        break
            t1 = time.perf_counter_ns()
            total_list_ms = (t1 - t0) / 1e6
            avg_list_ms = total_list_ms / len(lookup_items)

            # medir lookup dict (hash table)
            t0 = time.perf_counter_ns()
            found_count_dict = 0
            for q in lookup_items:
                qi = int.from_bytes(q, 'big')
                if qi in A_dict:
                    found_count_dict += 1
            t1 = time.perf_counter_ns()
            total_dict_ms = (t1 - t0) / 1e6
            avg_dict_ms = total_dict_ms / len(lookup_items)

            # medir lookup bloom filter
            t0 = time.perf_counter_ns()
            found_count_bloom = 0
            for q in lookup_items:
                if bloom.contains(q):
                    found_count_bloom += 1
            t1 = time.perf_counter_ns()
            total_bloom_ms = (t1 - t0) / 1e6
            avg_bloom_ms = total_bloom_ms / len(lookup_items)

            # agregar resultados
            results[p_bits][n] = {
                'sample_proofs': S,
                'gen_mean_ms': (sum(gen_times_ms) / len(gen_times_ms)) if gen_times_ms else float('nan'),
                'gen_median_ms': None,  # opcional, calcular se quiser
                'ver_total_ms': total_ver_ms,
                'ver_avg_ms': avg_ver_ms,
                'ver_throughput_ops_s': throughput_ops_s,
                'ver_accepted': accepted,
                'lookup': {
                    'queries': len(lookup_items),
                    'list_total_ms': total_list_ms,
                    'list_avg_ms': avg_list_ms,
                    'list_found': found_count_list,
                    'dict_total_ms': total_dict_ms,
                    'dict_avg_ms': avg_dict_ms,
                    'dict_found': found_count_dict,
                    'bloom_total_ms': total_bloom_ms,
                    'bloom_avg_ms': avg_bloom_ms,
                    'bloom_found': found_count_bloom,
                },
                'sizes_bytes': {
                    'p_bytes': (params.p.bit_length() + 7)//8,
                    'q_bytes': (params.q.bit_length() + 7)//8,
                    'proof_bytes': ((params.p.bit_length() + 7)//8) + ((params.q.bit_length() + 7)//8)
                }
            }

            # imprimir resumo para o caso de execução interativa
            import statistics
            print(f'Amostra provas: {S} -> gen média: {results[p_bits][n]["gen_mean_ms"]:.3f} ms | ver média: {results[p_bits][n]["ver_avg_ms"]:.3f} ms | throughput: {results[p_bits][n]["ver_throughput_ops_s"]:.1f} ops/s | aceitas: {accepted}/{len(proofs)}')
            print(f'Lookup [{len(lookup_items)} queries]: list avg {avg_list_ms:.6f} ms, dict avg {avg_dict_ms:.6f} ms, bloom avg {avg_bloom_ms:.6f} ms')
            print('Tamanhos (bytes):', results[p_bits][n]['sizes_bytes'])
    print('\n=== Fim do experimento de performance ===')
    return results

def print_results(results):
    for pbits in sorted(results):
        print(f"p = {pbits} bits")
        for n in sorted(results[pbits]):
            r = results[pbits][n]
            lookup = r['lookup']
            queries = lookup['queries']
            present = queries // 2
            absent = queries - present
            bloom_found = lookup['bloom_found']
            false_positives = bloom_found - present
            # evitar divisão por zero
            fpr = (false_positives / absent * 100) if absent > 0 else 0.0

            print(f"  tokens: {n}")
            print(f"    proofs sample: {r['sample_proofs']}")
            print(f"    gen mean: {r['gen_mean_ms']:.3f} ms | ver avg: {r['ver_avg_ms']:.3f} ms | "
                  f"throughput: {r['ver_throughput_ops_s']:.1f} ops/s | accepted: {r['ver_accepted']}/{r['sample_proofs']}")
            pbytes = r['sizes_bytes']['p_bytes']
            qbytes = r['sizes_bytes']['q_bytes']
            proof_bytes = r['sizes_bytes']['proof_bytes']
            print(f"    sizes: p {pbytes} B, q {qbytes} B, proof {proof_bytes} B")
            print(f"    lookup (queries={queries}):")
            # converter ms -> µs para avg mais legível quando muito pequeno
            print(f"      list: avg {lookup['list_avg_ms']*1000:.3f} µs (total {lookup['list_total_ms']:.3f} ms), "
                  f"found {lookup['list_found']}/{queries}")
            print(f"      dict: avg {lookup['dict_avg_ms']*1000:.3f} µs (total {lookup['dict_total_ms']:.3f} ms), "
                  f"found {lookup['dict_found']}/{queries}")
            print(f"      bloom: avg {lookup['bloom_avg_ms']*1000:.3f} µs (total {lookup['bloom_total_ms']:.3f} ms), "
                  f"found {lookup['bloom_found']}/{queries}, FPR ≈ {fpr:.2f}%")
        print()

    # ----------------------- Experimento 5: robustez contra ataques -----------------------

def _verify_with_options(A, Y, r, params, registered_As_set=None,
                         anti_replay=False, strict=False, seen_proofs=None):
    """
    Verifica uma prova com opções extras:
      - strict: checa intervalos (1 <= A < p, 1 <= Y < p, 0 <= r < q) antes da verificação criptográfica.
      - anti_replay: rejeita provas já vistas (A,Y,r) se seen_proofs fornecido.
      - registered_As_set: se fornecido, pode ser usado para detectar A não registrado.
    Retorna (accepted:bool, reason:str).
    """
    p = params.p; q = params.q
    # tipo/intervalo (validação estrita)
    if strict:
        if not isinstance(A, int) or not isinstance(Y, int) or not isinstance(r, int):
            return False, "malformed_type"
        if not (1 <= A < p):
            return False, "A_out_of_range"
        if not (1 <= Y < p):
            return False, "Y_out_of_range"
        if not (0 <= r < q):
            return False, "r_out_of_range"
    # A registrado?
    if registered_As_set is not None:
        if A not in registered_As_set:
            # deixar a verificação normal tratar (mas sinalizar como não-registrado)
            # aqui podemos decidir rejeitar imediatamente — para o experimento, só marcamos
            pass

    # anti-replay
    if anti_replay:
        if seen_proofs is None:
            seen_proofs = set()
        key = (A, Y, r)
        if key in seen_proofs:
            return False, "replay_detected"
        # registrar como visto (independentemente do resultado criptográfico)
        seen_proofs.add(key)

    # verificação criptográfica padrão
    try:
        ok = verificar_prova(A, Y, r, params)
    except Exception as e:
        return False, f"exception_verify:{e!r}"
    if not ok:
        return False, "crypto_reject"
    # se aceitou mas A não registrado, sinalizar apropriadamente
    if registered_As_set is not None and A not in registered_As_set:
        return True, "accepted_but_A_not_registered"
    return True, "accepted"

def experimento_robustez(params, voters, trials_per_scenario=200):
    """
    Quinto experimento: testa robustez contra vários ataques/entradas malformadas.
    - params: PublicParams já gerados
    - voters: lista de (a, A) credenciais registradas
    - trials_per_scenario: número de tentativas por cenário
    Retorna dicionário com resultados agregados por modo (proteções) e cenário.
    """
    # preparar conjunto de A registrados
    registered_As = {A for (_a, A) in voters}
    n = len(voters)
    results = {}

    # modos de proteção a testar
    modes = [
        ("no_protection", False, False),
        ("anti_replay_only", True, False),
        ("strict_only", False, True),
        ("anti_replay_and_strict", True, True),
    ]

    # definir cenários a simular
    # cada cenário: função que gera (A_submitted, Y_submitted, r_submitted, description)
    def scenario_replay(idx):
        # gera uma prova legítima e retorna duas submissões: (first, second)
        a, A = voters[idx]
        Y, r = gerar_prova(a, A, params)
        return (A, Y, r), (A, Y, r)  # replay: mesma prova duas vezes

    def scenario_A_not_registered(idx):
        # usa prova legítima, mas substitui A por um A' aleatório não registrado
        a, A = voters[idx]
        Y, r = gerar_prova(a, A, params)
        # achar A' que não esteja registrado (loop curto)
        attempts = 0
        while True:
            A_prime = secrets.randbelow(params.p - 2) + 2
            if A_prime not in registered_As:
                break
            attempts += 1
            if attempts > 20:
                # gerar algo óbvio fora do conjunto (p-1 is unlikely to be exactly a registered A)
                A_prime = params.p - 1
                break
        return (A_prime, Y, r)

    def scenario_malformed_values(idx):
        # tenta algumas formas de valores fora do domínio
        a, A = voters[idx]
        Y_ok, r_ok = gerar_prova(a, A, params)
        choices = []
        # Y = 0
        choices.append((A, 0, r_ok))
        # r = q (fora do intervalo 0..q-1)
        choices.append((A, Y_ok, params.q))
        # Y = p + 1 (fora de 0..p-1)
        choices.append((A, params.p + 1, r_ok))
        # r negative
        choices.append((A, Y_ok, -1))
        # A = 0
        choices.append((0, Y_ok, r_ok))
        return secrets.choice(choices)

    def scenario_forged_r(idx):
        # usa A legítimo e Y correto, mas r aleatório (forjado)
        a, A = voters[idx]
        Y = pow(params.g, secrets.randbelow(params.q), params.p)  # poderia usar Y legítimo
        r_bad = secrets.randbelow(params.q)
        return (A, Y, r_bad)

    def scenario_swap_A(idx):
        # pega prova de voters[idx] e submete com A de outro voter j != idx
        a, A = voters[idx]
        Y, r = gerar_prova(a, A, params)
        # escolher outro A diferente
        j = (idx + 1) % n if n > 1 else idx
        A_other = voters[j][1]
        return (A_other, Y, r)

    def scenario_random_proof(idx):
        # Y and r totalmente aleatórios (provavelmente inválidos)
        A = voters[idx][1]
        Y_rand = secrets.randbelow(params.p * 10)  # fora e dentro do domínio
        r_rand = secrets.randbelow(params.q * 10)
        return (A, Y_rand, r_rand)

    # mapa de cenário -> gerador
    scenario_generators = {
        "replay_valid": scenario_replay,
        "A_not_registered": scenario_A_not_registered,
        "malformed_values": scenario_malformed_values,
        "forged_r": scenario_forged_r,
        "swap_A": scenario_swap_A,
        "random_proof": scenario_random_proof,
    }

    # executar simulações para cada modo e cenário
    for mode_name, anti_replay, strict in modes:
        results[mode_name] = {}
        for scen_name, gen in scenario_generators.items():
            stats = {"attempts": 0, "accepted": 0, "rejected": 0, "details": {}}
            # special case for replay: each trial will submit twice and we care about both
            if scen_name == "replay_valid":
                # para replay, medir taxa de aceitação do primeiro e segundo envio
                first_accept = 0
                second_accept = 0
                for t in range(trials_per_scenario):
                    idx = secrets.randbelow(n)
                    (A1, Y1, r1), (A2, Y2, r2) = gen(idx)
                    seen = set() if anti_replay else None
                    ok1, reason1 = _verify_with_options(A1, Y1, r1, params,
                                                        registered_As_set=registered_As,
                                                        anti_replay=anti_replay,
                                                        strict=strict,
                                                        seen_proofs=seen)
                    # second submission uses same seen set to simulate same verifier state
                    ok2, reason2 = _verify_with_options(A2, Y2, r2, params,
                                                        registered_As_set=registered_As,
                                                        anti_replay=anti_replay,
                                                        strict=strict,
                                                        seen_proofs=seen)
                    first_accept += 1 if ok1 else 0
                    second_accept += 1 if ok2 else 0
                stats["attempts"] = trials_per_scenario
                stats["details"]["first_accept"] = first_accept
                stats["details"]["second_accept"] = second_accept
                stats["details"]["first_reject"] = trials_per_scenario - first_accept
                stats["details"]["second_reject"] = trials_per_scenario - second_accept
            else:
                # normal scenarios: single submission per trial
                reason_counts = {}
                for t in range(trials_per_scenario):
                    idx = secrets.randbelow(n)
                    A_sub, Y_sub, r_sub = gen(idx)
                    # iniciar seen_proofs vazio apenas se anti_replay for True (simulador por prover/verificador único)
                    seen = set() if anti_replay else None
                    ok, reason = _verify_with_options(A_sub, Y_sub, r_sub, params,
                                                      registered_As_set=registered_As,
                                                      anti_replay=anti_replay,
                                                      strict=strict,
                                                      seen_proofs=seen)
                    stats["attempts"] += 1
                    if ok:
                        stats["accepted"] += 1
                    else:
                        stats["rejected"] += 1
                    reason_counts[reason] = reason_counts.get(reason, 0) + 1
                stats["details"] = reason_counts
            results[mode_name][scen_name] = stats

    print("\n=== Relatório do Experimento de Robustez (Resumo) ===")
    for mode_name in results:
        print(f"\nModo: {mode_name} (anti_replay={'yes' if 'anti_replay' in mode_name else 'no'}, strict={'yes' if 'strict' in mode_name else 'no'})")
        for scen_name, stats in results[mode_name].items():
            if scen_name == "replay_valid":
                fa = stats["details"]["first_accept"]
                sa = stats["details"]["second_accept"]
                print(f"  {scen_name}: trials={stats['attempts']}, first_accept={fa}/{stats['attempts']}, second_accept={sa}/{stats['attempts']}")
            else:
                print(f"  {scen_name}: trials={stats['attempts']}, accepted={stats['accepted']}, rejected={stats['rejected']}")
                # mostrar contagem por razão (quando útil)
                if isinstance(stats.get("details"), dict):
                    # limitar linhas longas
                    detail_items = sorted(stats["details"].items(), key=lambda x: -x[1])
                    detail_str = ", ".join(f"{k}:{v}" for k, v in detail_items[:6])
                    print(f"    reasons: {detail_str}")
    print("====================================================\n")
    return results
# ----------------------------- Execução do experimento -------------------------------
def main(run_perf=False,run_robust = False):
    # Parâmetros para demo: n=50, p_bits=512 (experimento funcional original)
    params, voters = experimento_funcional(n=50, p_bits=512, corrupt_fraction=0.04)

    # Teste adicional de segurança
    a0, A0 = voters[0]
    a1, A1 = voters[1]
    Y0, r0 = gerar_prova(a0, A0, params)
    print('\nTeste adicional de segurança: prova válida com A trocado (deve ser rejeitada)')
    print('Verificação com A correto:', verificar_prova(A0, Y0, r0, params))
    print('Verificação com A trocado:', verificar_prova(A1, Y0, r0, params))

    # -------- Exemplo de execução do Experimento 4  --------------
    # Observação: gerar primes grandes e muitos tokens pode levar bastante tempo.
    if run_perf:
        results = experimento_performance_scalabilidade(
            p_bits_list=[256, 512],    # mudar para [512, 1024] para testar parâmetros maiores
            token_counts=[1000, 5000], # números de tokens a testar (aumente para testar escala)
            sample_proofs=200,         # amostra para medir latência de geração/verificação
            lookup_queries=5000        # número de consultas para medir custo de lookup
        )
        try:
            print_results(results)
        except NameError:
            print(results)
    if run_robust:
        print("Executando Experimento 5: robustez/ataques (pode demorar)...")
        results_robust = experimento_robustez(params, voters, trials_per_scenario=200)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Demo / runner para protocolo e experimentos.")
    parser.add_argument('--run-perf', action='store_true',
                        help='Pode demorar bastante.')
    parser.add_argument('--run-robust', action='store_true', help='Executa o Experimento 5 (robustez).')
    args = parser.parse_args()
    main(run_perf=args.run_perf,run_robust=args.run_robust)
