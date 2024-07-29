import os
import argparse
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor

# List of required tools
REQUIRED_TOOLS = ["subfinder", "amass", "httprobe", "nuclei", "katana", "ffuf", "gau"]

def run_command(cmd):
    try:
        subprocess.run(cmd, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {cmd}\n{e}")

def check_tool_installed(tool):
    return shutil.which(tool) is not None

def install_tool(tool):
    go_path = os.path.expanduser("~/.go")
    os.environ["GOPATH"] = go_path
    os.environ["PATH"] += os.pathsep + os.path.join(go_path, "bin")
    
    try:
        if tool == "httprobe":
            subprocess.check_call(["go", "install", "github.com/tomnomnom/httprobe@latest"])
        elif tool == "ffuf":
            subprocess.check_call(["go", "install",  "github.com/ffuf/ffuf@latest"])
        elif tool == "gau":
            subprocess.check_call(["go", "install",  "github.com/lc/gau/v2/cmd/gau@latest"])
        else:
            subprocess.check_call(["go", "install",  f"github.com/projectdiscovery/{tool}/cmd/{tool}@latest"])
    except subprocess.CalledProcessError as e:
        print(f"Error installing {tool}: {e}")

def check_and_install_tools():
    for tool in REQUIRED_TOOLS:
        if not check_tool_installed(tool):
            print(f"{tool} is not installed. Installing...")
            install_tool(tool)
            os.system("clear")

def create_directories(directories):
    for dir_path in directories:
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)

def main(target, threads=5):
    check_and_install_tools()
    print("* Running Dynamic Application Security Testing (DAST) *\n All the Outputs can be read in Targets/\n Note: This may take some time")

    targets_dir = "Targets"
    subdomains_dir = os.path.join(targets_dir, "Subdomains")
    vulns_dir = os.path.join(targets_dir, "Vulns")
    webapp_content_dir = os.path.join(targets_dir, "WebAppContent")
    create_directories([targets_dir, subdomains_dir, vulns_dir, webapp_content_dir])

    subs_file = os.path.join(subdomains_dir, f"{target}.subs")

    # Subdomain discovery
    run_command(f"subfinder -d {target} -silent >> {subs_file}")
    run_command(f"amass enum -d {target} >> {subs_file}")

    # HTTP/HTTPS probing
    httpprobe_file = os.path.join(subdomains_dir, f"{target}.httpprobe")
    with ThreadPoolExecutor(max_workers=threads) as executor:
        executor.submit(run_command, f"cat {subs_file} | httprobe -c {threads} | tee {httpprobe_file}")

    # Discovery
    run_command("wget -O /tmp/common.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt")

    katana_output_file = os.path.join(webapp_content_dir, f"{target}.katana")
    run_command(f"katana -no-color -system-chrome -list {httpprobe_file} -output {katana_output_file}")

    ffuf_output_file = os.path.join(webapp_content_dir, f"{target}.ffuf")
    run_command(f"ffuf -u HOST/WORD -w {httpprobe_file}:HOST -w /tmp/common.txt:WORD -ac -o {ffuf_output_file}")

    gau_output_file = os.path.join(webapp_content_dir, f"{target}.gau")
    run_command(f"cat {httpprobe_file} | xargs -n1 -I{{}} sh -c 'echo {{}} | gau --subs --threads {threads}' | tee {gau_output_file}")

    webapp_content_urls_file = os.path.join(webapp_content_dir, f"{target}.urls")
    run_command(f"cat {katana_output_file} $(jq -r '.results[].url' {ffuf_output_file}) | sort -u >> {webapp_content_urls_file}")

    # Run Nuclei Scan
    nuclei_output_file = os.path.join(vulns_dir, f"{target}.nuclei")
    run_command(f"nuclei -l {httpprobe_file} -t ~/nuclei-templates/ -o {nuclei_output_file} -es info,low")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Simple Vulnerability Discovery DAST')
    parser.add_argument('target', type=str, help='Target to scan')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads to use')
    args = parser.parse_args()
    main(args.target, args.threads)
