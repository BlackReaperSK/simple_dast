import argparse
import os
import threading

# Achar os subdominios do alvo
def find_subdomains(target, output_file):

    subfinder_command = f"subfinder -d {target} -silent >> {output_file}"
    amass_command = f"amass enum -d {target} >> {output_file}"
    os.system(subfinder_command)
    os.system(amass_command)
    print(f"Subdomínios encontrados para {target} estão em {os.path.abspath(output_file)}")

# Ver qual subdominios estão com serviços HTTP/HTTPS
def httpprobe(input_file, output_file):

    httprobe_command = f"cat {input_file} | httprobe | tee {output_file}"
    os.system(httprobe_command)
    print(f"Subdomínios com serviços HTTP(S) encontrados em {os.path.abspath(output_file)}")

# Web Discovery
def discover(input_file, output_file):

    os.system("wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt")
    katana_command = f"katana -no-color -system-chrome  -list {input_file} -output katana_output.txt"
    gau_command = f"cat {input_file} | xargs -n1 -I{{}} sh -c 'echo {{}} | gau --subs --threads 5' | tee gau_output.txt"

    ffuf_command = f"ffuf -u HOST/WORD -w {input_file}:HOST -w common.txt:WORD -ac -o fuff.txt"
    os.system(katana_command)
    os.system(gau_command)
    os.system(ffuf_command)
    os.system(f"cat *_output.txt $(jq -r '.results[].url' fuff.txt) | sort -n | uniq >> {output_discover}")
    print(f"Processo de coleta de URLs em {os.path.abspath(output_file)}")

# Start
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Simple Content Discover DAST')
    parser.add_argument('target', type=str, help='Alvo do scan')
    args = parser.parse_args()
    
    # Encontra subdominios em paralelo
    output_subs = f"{args.target}_subdomains.txt"
    subdomain_thread = threading.Thread(target=find_subdomains, args=(args.target, output_subs))
    subdomain_thread.start()
    
    # Espera a thread terminar para prosseguir com httpprobe
    subdomain_thread.join()
    output_httpprobe = f"{args.target}_httpprobe.txt"
    httpprobe_thread = threading.Thread(target=httpprobe, args=(output_subs, output_httpprobe))
    httpprobe_thread.start()
    
    # Espera a thread terminar para prosseguir com discover
    httpprobe_thread.join()
    output_discover = f"collect_urls_{args.target}.txt"
    discover_thread = threading.Thread(target=discover, args=(output_httpprobe, output_discover))
    discover_thread.start()
    
    # Espera a thread terminar para encerrar o programa
    discover_thread.join()
