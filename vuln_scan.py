import os, argparse, shutil, subprocess
from concurrent.futures import ThreadPoolExecutor

# List of required tools
required_tools = ["subfinder", "amass", "httprobe", "nuclei"]

def run_cmd(cmd): os.system(cmd)

def check_tool_installed(tool):
    return shutil.which(tool) is not None

def install_tool(tool):
    if tool == "httprobe":
        subprocess.check_call(["go", "get", "-u", "github.com/tomnomnom/httprobe"])
    else:
        subprocess.check_call(["go", "get", "-u", f"github.com/projectdiscovery/{tool}/cmd/{tool}"])

def check_and_install_tools():
    for tool in required_tools:
        if not check_tool_installed(tool):
            print(f"{tool} is not installed. Installing...")
            install_tool(tool)

def set_gopath():
    go_path = os.path.expanduser("~/.go")
    os.environ["GOPATH"] = go_path
    os.environ["PATH"] += os.pathsep + os.path.join(go_path, "bin")

def main(target, threads=5):
    check_and_install_tools()

    targets_dir = "Targets"
    if not os.path.exists(targets_dir):
        os.makedirs(targets_dir)

    subdomains_dir = os.path.join(targets_dir, "Subdomains")
    vulns_dir = os.path.join(targets_dir, "Vulns")
    for dir_path in [subdomains_dir, vulns_dir]:
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)

    subs = os.path.join(subdomains_dir, f"{target}.subs")
    os.system(f"subfinder -d {target} -silent >> {subs}")
    os.system(f"amass enum -d {target} >> {subs}")
    httpprobe = os.path.join(subdomains_dir, f"{target}.httpprobe")
    with ThreadPoolExecutor(max_workers=threads) as executor:
        executor.submit(run_cmd, f"cat {subs} | httprobe -c {threads} | tee {httpprobe}")

    nuclei_output = os.path.join(vulns_dir, f"{target}.nuclei")
    os.system(f"nuclei -l {httpprobe} -t ~/nuclei-templates/ -o {nuclei_output} -es info,low")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Simple Vulnerability Discovery DAST')
    parser.add_argument('target', type=str, help='Alvo do scan')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Threads Number to set')
    args = parser.parse_args()
    set_gopath()
    main(args.target, args.threads)
