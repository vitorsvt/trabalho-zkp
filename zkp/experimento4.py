import time

from zkp.utility import *

# ----------------------- Experimento 4: Performance e Escalabilidade ------------------

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
