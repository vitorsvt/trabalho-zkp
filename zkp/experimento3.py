from zkp.utility import *

# ----------------------- Experimento 3: Medição de Desvinculação ------------------

def simulate_proof_generation(num_voters, proofs_per_voter, insecure=False):
    """
    Simula a geração de provas por múltiplos eleitores.
    Retorna uma lista de tuplas: [(ID_real, A, Y, r), ...]
    """
    data = []
    
    for i in range(num_voters):
        # Geração da Credencial Secreta
        params = setup(p_bits=128, print_output=False)
        a, A = keygen(params)
        real_id = f"Voter_{i}"
        
        for j in range(proofs_per_voter):
            # 2. Geração da Prova
            if not insecure: # Utilizando função correta
                Y, r = gerar_prova(a, A, params)
            else:  # Utilizando função com baixa entropia em y (insegura)
                Y, r = gerar_prova_insegura(a, A, params)
            
            # 3. Armazenamento: (ID real não deve ser usado na análise)
            data.append({
                'A_token': A,         # Token público (A)
                'Y': Y,               # Compromisso da Prova (Y)
                'r': r,               # Resposta da Prova (r)
                'ground_truth': real_id # ID real (usado apenas para verificar o resultado)
            })
    return data

def measure_unlinkability(simulated_data):
    # 1. Agrupamento pelo Token Público (A) - O Observador Sabe A
    # Isso simula um observador que rastreia os tokens públicos:
    grouped_by_token = {}
    for entry in simulated_data:
        A = entry['A_token']
        if A not in grouped_by_token:
            grouped_by_token[A] = []
        grouped_by_token[A].append((entry['Y'], entry['r']))

    # 2. Análise de Correlação (Medindo a Desvinculação)
    total_proofs = len(simulated_data)
    
    # O teste de unlinkability aqui é se as provas dentro de CADA grupo
    # (agrupado por A) parecem aleatórias entre si.

    # METRICA CHAVE: Rejeição de Reuso de Provas
    # A desvinculação é garantida se NENHUM par (Y, r) se repetir para o mesmo A.
    # Se o RNG for fresco (y novo), todas as provas (Y, r) DEVERÃO ser únicas.
    
    repeat_count = 0
    total_groups = len(grouped_by_token)

    for A, proofs in grouped_by_token.items():
        # Verifica se há repetição de prova (Y, r) dentro do grupo A
        if len(proofs) != len(set(proofs)):
            # Se houver repetição, indica falha na aleatoriedade de y
            repeat_count += 1
    
    # Taxa de Desvinculação (Baseado na não-repetição)
    # Se repeat_count for 0, o sistema é perfeitamente desvinculado (dentro da prova)
    unlinkability_rate = 1.0 - (repeat_count / total_groups)
    
    return {
        "Total de Provas": total_proofs,
        "Total de Eleitores (Grupos A)": total_groups,
        "Grupos com Provas Repetidas": repeat_count,
        "Taxa de Desvinculação (Não Repetição)": unlinkability_rate
    }
