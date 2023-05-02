import os, sys, argparse
from concurrent.futures import ThreadPoolExecutor

def run_cmd(cmd): os.system(cmd)

def main(target, threads=5):
    subs = f"{target}.subs"
    os.system(f"subfinder -d {target} -silent >> {subs}")
    os.system(f"amass enum -d {target} >> {subs}")
    httpprobe = f"{target}.httpprobe"
    with ThreadPoolExecutor(max_workers=threads) as executor:
        executor.submit(run_cmd, f"cat {subs} | httprobe -c {threads} | tee {httpprobe}")
    os.system(f"nuclei -l {httpprobe} -t ~/.local/nuclei-templates/ -o {target}.nuclei -es info,low")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Simple Content Discover DAST')
    parser.add_argument('target', type=str, help='Alvo do scan')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Número de threads para usar')
    args = parser.parse_args()
    main(args.target, args.threads)
