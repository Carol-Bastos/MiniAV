import os
import hashlib
import sys
import argparse

def load_signatures(db_path):
    """Carrega assinaturas do arquivo de banco de dados."""
    signatures = {}
    try:
        with open(db_path, 'r') as f:
            for line in f:
                if line.startswith('#') or line.strip() == '':
                    continue
                hash_val, name = line.strip().split(':')
                signatures[hash_val] = name
    except FileNotFoundError:
        print(f"[ERRO] Banco de dados não encontrado: {db_path}")
        sys.exit(1)
    return signatures

def calculate_md5(file_path):
    """Calcula o hash MD5 de um arquivo."""
    try:
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except (IOError, OSError):
        return None

def scan_directory(directory, signatures):
    """Varre o diretório em busca de assinaturas conhecidas."""
    infected_files = []
    clean_files = 0

    print(f"[INFO] Iniciando varredura em: {directory}")
    print("-" * 50)

    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = calculate_md5(file_path)

            if file_hash in signatures:
                malware_name = signatures[file_hash]
                print(f"[ALERTA!] 🚨 Malware detectado: {file_path}")
                print(f"[ID] Assinatura: {malware_name} (Hash: {file_hash})")
                infected_files.append(file_path)
            else:
                clean_files += 1

    print("-" * 50)
    print(f"[RESUMO] Arquivos limpos: {clean_files}")
    print(f"[RESUMO] Arquivos infectados: {len(infected_files)}")
    print("[STATUS] Análise concluída.")

    return infected_files

def main():
    parser = argparse.ArgumentParser(description="MiniAV - Scanner de Assinaturas Simples")
    parser.add_argument("-d", "--directory", required=True, help="Diretório para varredura (ex: /home/kali/Downloads)")
    parser.add_argument("-db", "--database", default="signatures.db", help="Caminho para o banco de dados de assinaturas")
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print(f"[ERRO] Diretório não encontrado: {args.directory}")
        sys.exit(1)

    signatures = load_signatures(args.database)
    if not signatures:
        print("[ERRO] Banco de dados vazio ou inválido.")
        sys.exit(1)

    scan_directory(args.directory, signatures)

if __name__ == "__main__":
    main()

