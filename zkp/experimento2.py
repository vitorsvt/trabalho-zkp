from zkp.utility import (
    setup,
    keygen,
    gerar_prova,
    gerar_prova_insegura,
    hash_to_zq,
    hash_to_zq_insecure,
)

import numpy as np
from scipy.stats import chisquare, pearsonr

# ----------------------- Experimento 3: Teste de Resistência ------------------

def experimento_resistencia(n=10000, p_bits=512, insecure=False):
    """
    Execução do segundo experimento

    Args:
        n (int): quantidade de provas a serem geradas (por eleitor)
        p_bits (int): tamanho do primo a ser gerado pelo setup
    """

    params = setup(p_bits)

    def pvalue(values: list[int]):
        """
        Função auxiliar para checar uma distribuição,
        por meio do teste de uniformidade (qui-quadrado)

        Args:
            values (list[int])
        """

        # Número de bins para o teste
        bins = int(n**0.5)

        # Transformar em números de tamanho apropriado ao numpy
        reduced = np.array([v / params.q for v in values], dtype=float)
        # Gerar o histograma observado
        observed, _ = np.histogram(reduced, bins=bins)
        # Gerar o histograma esperado
        expected = np.full(bins, len(values) / bins)

        _, pvalue = chisquare(observed, expected)

        return pvalue

    # Caso houve repetição de Y em alguma das provas geradas
    repeated = False

    # Geração de um eleitor
    a, A = keygen(params)

    Ys = {}  # Dicionário para Y gerados em provas
    cs = []  # Lista de valores de c
    rs = []  # Lista de valores de r

    for _ in range(n):
        if not insecure:
            Y, r = gerar_prova(a, A, params)
            c = hash_to_zq(A, Y, params.q)
        else:
            Y, r = gerar_prova_insegura(a, A, params)
            c = hash_to_zq_insecure(A, Y, params.q)

        if Y in Ys:  # Caso o Y já tenha sido registrado
            repeated = True
            continue

        Ys[Y] = (r, c)
        cs.append(c)
        rs.append(r)

    # Checar as distribuições por meio do teste do qui quadrado

    cs_pvalue = pvalue(cs)
    if cs_pvalue < 0.05:
        print('❌ p-value de "c" < 0.05, rejeição da hipótese nula')
    else:
        print('✅ Valor-p para "c" não rejeita a hipótese nula')

    rs_pvalue = pvalue(rs)
    if rs_pvalue < 0.05:
        print('❌ p-value de "r" < 0.05, rejeição da hipótese nula')
    else:
        print('✅ Valor-p para "r" não rejeita a hipótese nula')

    # Checar correlação nas distribuições de r

    rs_normalized = [v / params.q for v in rs]
    rs_current = rs_normalized[:-1]
    rs_next = rs_normalized[1:]
    result = pearsonr(rs_current, rs_next)
    correlation = result.correlation

    print("Correlação de Pearson (r[i] vs r[i+1])")

    if abs(correlation) > 0.05:
        print("❌ Correlação significativa identificada entre provas consecutivas")
    else:
        print("✅ Correlação próxima a zero")

    if repeated:
        print("❌ Y repetido obtido de provas distintas")
    else:
        print("✅ Não foi possível extrair 'a' de nenhum eleitor")