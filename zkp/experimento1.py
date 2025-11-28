from utility import *

# ----------------------- Experimento 1: Validade Funcional do Esquema ------------------

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
