from zkp.utility import *

# ----------------------- Experimento 5: Robustez Contra Ataques -----------------------

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
