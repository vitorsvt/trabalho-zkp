
from zkp.utility import *

from zkp.experimento1 import experimento_funcional
from zkp.experimento2 import experimento_resistencia
from zkp.experimento3 import simulate_proof_generation, measure_unlinkability
from zkp.experimento4 import experimento_performance_scalabilidade, print_results
from zkp.experimento5 import experimento_robustez

# ----------------------------- Execução dos experimentos -------------------------------
def main(run_perf=False,run_robust = False):
    # -------- Exemplo de execução do Experimento 1  --------------
    print("---------- EXECUTANDO EXPERIMENTO 1 - VALIDADE FUNCIONAL ----------\n")

    # Parâmetros para demo: n=50, p_bits=512 (experimento funcional original)
    params, voters = experimento_funcional(n=50, p_bits=512, corrupt_fraction=0.04)

    # Teste adicional de segurança
    a0, A0 = voters[0]
    a1, A1 = voters[1]
    Y0, r0 = gerar_prova(a0, A0, params)
    print('\nTeste adicional de segurança: prova válida com A trocado (deve ser rejeitada)')
    print('Verificação com A correto:', verificar_prova(A0, Y0, r0, params))
    print('Verificação com A trocado:', verificar_prova(A1, Y0, r0, params))

    # -------- Exemplo de execução do Experimento 2 ---------------
    print("\n---------- EXECUTANDO EXPERIMENTO 2 - TESTE DE RESISTÊNCIA ----------\n")
    print("\nTeste de Resistência com Prova e Hash seguros:\n")
    experimento_resistencia()
    
    print("\nTeste de Resistência com Prova e Hash inseguros:\n")
    experimento_resistencia(insecure=True)

    # -------- Exemplo de execução do Experimento 3  --------------
    print("\n---------- EXECUTANDO EXPERIMENTO 3 - MEDIÇÃO DE DESVINCULAÇÃO ----------\n")

    # Rodando teste seguro utilizando funções implementadas corretamente (100% Unlinkability)
    print("Teste de Unlinkability com Provas Seguras:\n")
    simulated_data = simulate_proof_generation(num_voters=20, proofs_per_voter=5)
    unlinkability_results = measure_unlinkability(simulated_data)
    print(unlinkability_results)

    # Rodando teste inseguro utilizando função de prova insegura (Unlinkability < 100%)
    # Devido à menor entropia em y, esperamos que algumas provas se repitam.
    print("\nTeste de Unlinkability com Geração de Provas com Baixa Entropia:\n")
    simulated_data = simulate_proof_generation(num_voters=20, proofs_per_voter=5, insecure=True)
    unlinkability_results = measure_unlinkability(simulated_data)
    print(unlinkability_results)

    # -------- Exemplo de execução do Experimento 4  --------------

    # Observação: gerar primes grandes e muitos tokens pode levar bastante tempo.
    if run_perf:
        print("\n---------- EXECUTANDO EXPERIMENTO 4 - PERFORMANCE E ESCALABILIDADE ----------\n")
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

    # -------- Exemplo de execução do Experimento 5  --------------

    if run_robust:
        print("\n---------- EXECUTANDO EXPERIMENTO 5 - ROBUSTEZ CONTRA ATAQUES ----------\n")
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
