import os,argparse,shutil,subprocess,threading
from concurrent.futures import ThreadPoolExecutor

# List of required tools
required_tools = ["subfinder", "amass", "httprobe", "nuclei", "katana", "ffuf", "gau"]
def run_cmd(cmd): os.system(cmd)

# VERIFY/INSTALL TOOLS
def check_tool_installed(tool):
    return shutil.which(tool) is not None
def install_tool(tool):
    if tool == "httprobe":
        subprocess.check_call(["go", "install", "github.com/tomnomnom/httprobe@latest"])
    elif tool == "ffuf":
        subprocess.check_call(["go", "install",  "github.com/ffuf/ffuf@latest"])
    elif tool == "gau":
        subprocess.check_call(["go", "install",  "github.com/lc/gau/v2/cmd/gau@latest"])
    else:
        subprocess.check_call(["go", "install",  f"github.com/projectdiscovery/{tool}/cmd/{tool}@latest"])
    go_path = os.path.expanduser("~/.go")
    os.environ["GOPATH"] = go_path
    os.environ["PATH"] += os.pathsep + os.path.join(go_path, "bin")
def check_and_install_tools():
    for tool in required_tools:
        if not check_tool_installed(tool):
            print(f"{tool} is not installed. Installing...")
            install_tool(tool)
            os.system("clear")

# DAST Weaponize
def main(target, threads=5):
    check_and_install_tools()
    print("* Running Dynamic Application Security Testing (DAST) *\n All the Outputs can be read on Targets/\n Note: This may take some time")
    targets_dir = "Targets"
    if not os.path.exists(targets_dir):
        os.makedirs(targets_dir)
    subdomains_dir = os.path.join(targets_dir, "Subdomains")
    vulns_dir = os.path.join(targets_dir, "Vulns")
    infog_dir = os.path.join(targets_dir, "WebAppContent")
    for dir_path in [subdomains_dir, vulns_dir, infog_dir]:
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
    subs = os.path.join(subdomains_dir, f"{target}.subs")
    # Subdomains
    os.system(f"subfinder -d {target} -silent >> {subs}")
    os.system(f"amass enum -d {target} >> {subs}")
    # Set HTTP/HTTPS
    httpprobe = os.path.join(subdomains_dir, f"{target}.httpprobe")
    with ThreadPoolExecutor(max_workers=threads) as executor:
        executor.submit(run_cmd, f"cat {subs} | httprobe -c {threads} | tee {httpprobe}")
    # Discovery
    os.system("wget -O /tmp/common.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt")
    katana_output = os.path.join(infog_dir, f"{target}.katana")
    os.system(f"katana -no-color -system-chrome  -list {httpprobe} -output {katana_output}")

    ffuf_output = os.path.join(infog_dir, f"{target}.fuff")
    os.system(f"ffuf -u HOST/WORD -w {httpprobe}:HOST -w /tmp/common.txt:WORD -ac -o {ffuf_output}")

    gau_output = os.path.join(infog_dir, f"{target}.gau")
    os.system(f"cat {httpprobe} | xargs -n1 -I{{}} sh -c 'echo {{}} | gau --subs --threads {threads}' | tee {gau_output}")
    os.system(f" cat Targets/WebAppContent/{target}.* $(jq -r '.results[].url' {ffuf_output}) | sort -n | uniq >> Targets/WebAppContent/{target}.urls")
   
    # Run Nuclei Scan
    nuclei_output = os.path.join(vulns_dir, f"{target}.nuclei")
    os.system(f"nuclei -l {httpprobe} -t ~/nuclei-templates/ -o {nuclei_output} -es info,low")


# Init
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Simple Vulnerability Discovery DAST')
    parser.add_argument('target', type=str, help='Alvo do scan')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Threads Number to set')
    args = parser.parse_args()
    main(args.target, args.threads)
