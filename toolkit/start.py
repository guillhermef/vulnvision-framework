from sys import argv
import requests
import subprocess
import argparse
import json
import re
from datetime import datetime, timedelta

#################################### BASIC FUNCTIONS ####################################

def arg_parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d','--domain', help='Name of the Root/Seed FQDN', required=True)
    return parser.parse_args()

def get_home_dir():
    get_home_dir = subprocess.run(["echo $HOME"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, shell=True)
    return get_home_dir.stdout.replace("\n", "")

def check_dir():
    home_dir = get_home_dir()
    go_check = subprocess.run([f"ls {home_dir}/recon/data/{args.domain}"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, shell=True)
    if go_check.returncode == 0:
        print(f"[!] {args.domain} folder already exist!")
        return True
    print(f"[!] {args.domain} folder was NOT found. Creating now...")
    return False

def create_dir():
    home_dir = get_home_dir()
    subprocess.run([f"mkdir {home_dir}/recon/data/{args.domain}"], shell=True)
    subprocess.run([f"mkdir {home_dir}/recon/data/{args.domain}/temp"], shell=True)

def build_cewl_wordlist(args):
    try:
        subprocess.run([f'ls; cewl -d 2 -m 5 -o -a -v -w wordlists/cewl_{args.domain}.txt https://www.{args.domain}'], shell=True)
    except Exception as e:
        print(f"CeWL Failed to Build Custom Wordlist! -> {args.domain}")

def sort_subdomains(home_dir, args):
    try:
        subprocess.run([f'cd {home_dir}/recon/data/{args.domain}/temp; cat *.tmp | {home_dir}/go/bin/anew uniques.tmp'], shell=True)
    except Exception as e:
        print(f"Anew failed to build a sorted list of subdomains! -> {args.domain}")


def cleanup(home_dir, args):
    subprocess.run([f"rm wordlists/crawl_*"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    subprocess.run([f"rm wordlists/cewl_*"],  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    subprocess.run([f"rm wordlists/live_*"],  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    subprocess.run([f"rm {home_dir}/recon/data/{args.domain}/temp/*.tmp"],  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    subprocess.run([f"rm log/nuclei*.dump"],  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)


def send_slack_notification(home_dir, text):
    message_json = {
        "text":text,
        "username":"Mensageiro"
    }
    f = open(f'{home_dir}/.keys/slack_web_hook')
    token = f.read()
    clean_token = token.replace(u"\u000a","")
    requests.post(f'https://hooks.slack.com/services/{clean_token}', json=message_json)

#################################### TOOLS ####################################

def extract_subdomains(url, domain):
    try:
        response = requests.get(url)
        response.raise_for_status()
        pattern = re.compile(rf'[a-zA-Z0-9]+(?:\.[a-zA-Z0-9]+)*\.{domain}')
        return set(pattern.findall(response.text))
    except requests.exceptions.RequestException as e:
        print(f"Error fetching subdomains from {url}: {e}")
        return set()


def apis(args, home_dir):
    all_subdomains = set()
    
    apis = [
        f'https://rapiddns.io/subdomain/{args.domain}?full=1#result',
        f'http://web.archive.org/cdx/search/cdx?url=*.{args.domain}/*&output=text&fl=original&collapse=urlkey',
        f'https://crt.sh/?q=%.{args.domain}',
        f'https://crt.sh/?q=%.%.{args.domain}',
        f'https://crt.sh/?q=%.%.%.{args.domain}',
        f'https://crt.sh/?q=%.%.%.%.{args.domain}',
        f'https://otx.alienvault.com/api/v1/indicators/domain/{args.domain}/passive_dns',
        f'https://api.hackertarget.com/hostsearch/?q={args.domain}',
        f'https://urlscan.io/api/v1/search/?q={args.domain}',
        f'https://jldc.me/anubis/subdomains/{args.domain}'
    ]
    
    for url in apis:
        subdomains = extract_subdomains(url, args.domain)
        all_subdomains.update(subdomains)
        with open (f"{home_dir}/recon/data/{args.domain}/temp/apis_subdomains.tmp", 'w') as file:
            for subs in all_subdomains:
                file.write(f"{subs}\n")

def subfinder(args, home_dir):
    try:
        subprocess.run([f'{home_dir}/go/bin/subfinder -d {args.domain} -o {home_dir}/recon/data/{args.domain}/temp/subfinder.tmp'], shell=True)
        f = open(f"{home_dir}/recon/data/{args.domain}/temp/subfinder.tmp", "r")
        subfinder_arr = f.read().rstrip().split("\n")
        f.close()
        subdomains_found = len(subfinder_arr)
        print(f"[MSG] subfinder completed successfully: {subdomains_found} results found")
    except Exception as e:
        print(f"[!] Something went wrong! Exception: {str(e)}")

def subfinder_recursive(args, home_dir):
    try:
        subprocess.run([f'{home_dir}/go/bin/subfinder -d {args.domain} -recursive -o {home_dir}/recon/data/{args.domain}/temp/subfinder.tmp'], shell=True)
        f = open(f"{home_dir}/recon/data/{args.domain}/temp/subfinder.tmp", "r")
        subfinder_arr = f.read().rstrip().split("\n")
        f.close()
        subdomains_found = len(subfinder_arr)
        print(f"[MSG] subfinder recursive completed successfully: {subdomains_found} results found")
    except Exception as e:
        print(f"[!] Something went wrong!  Exception: {str(e)}")


def sublist3r(args, home_dir):
    try:
        subprocess.run([f"python3 {home_dir}/Tools/Sublist3r/sublist3r.py -d {args.domain} -t 50 -o {home_dir}/recon/data/{args.domain}/temp/sublist3r.tmp"], text=True, shell=True)
        f = open(f"{home_dir}/recon/data/{args.domain}/temp/sublist3r.tmp", "r")
        sublist3r_arr = f.read().rstrip().split("\n")
        f.close()
        subdomains_found = len(sublist3r_arr)
        print(f"[MSG] sublist3r completed successfully: {subdomains_found} results found")
    except Exception as e:
        if """[Errno 2] No such file or directory: './temp/sublist3r.tmp'""" not in str(e):
            print(f"[!] Something went wrong!  Exception: {str(e)}")
        else:
            print("[-] Sublist3r did not find any results.  Continuing scan...")


def assetfinder(args, home_dir):
    try:
        subprocess.run([f"{home_dir}/go/bin/assetfinder --subs-only {args.domain} > {home_dir}/recon/data/{args.domain}/temp/assetfinder.tmp"], shell=True)
        f = open(f"{home_dir}/recon/data/{args.domain}/temp/assetfinder.tmp", "r")
        assetfinder_arr = f.read().rstrip().split("\n")
        f.close()
        subdomains_found = len(assetfinder_arr)
        print(f"[MSG] assetfinder completed successfully: {subdomains_found} results found")
    except Exception as e:
        print(f"[!] Something went wrong!  Exception: {str(e)}")

def gau(args, home_dir):
    try:
        subprocess.run([f"{home_dir}/go/bin/gau --subs {args.domain} | cut -d / -f 3 | sort -u > {home_dir}/recon/data/{args.domain}/temp/gau.tmp"], shell=True)
        f = open(f"{home_dir}/recon/data/{args.domain}/temp/gau.tmp", "r")
        gau_arr = f.read().rstrip().split("\n")
        f.close()
        subdomains_found = len(gau_arr)
        print(f"[MSG] GAU completed successfully: {subdomains_found} results found")
    except Exception as e:
        print(f"[!] Something went wrong!  Exception: {str(e)}")


def crt(args, home_dir):
    try:
        subprocess.run([f"{home_dir}/Tools/tlshelpers/getsubdomain {args.domain} > {home_dir}/recon/data/{args.domain}/temp/ctl.tmp"], shell=True)
        f = open(f"{home_dir}/recon/data/{args.domain}/temp/ctl.tmp", "r")
        ctl_arr = f.read().rstrip().split("\n")
        f.close()
        subdomains_found = len(ctl_arr)
        print(f"[MSG] CRT Completed Successfully: {subdomains_found} Results Found")
    except Exception as e:
        print(f"[!] Something went wrong!  Exception: {str(e)}")

def shuffle_dns(args, home_dir):
    try:
        subprocess.run([f'echo {args.domain} | {home_dir}/go/bin/shuffledns -w wordlists/all.txt -r wordlists/resolvers.txt -o {home_dir}/recon/data/{args.domain}/temp/shuffledns.tmp'], shell=True)
        f = open(f"{home_dir}/recon/data/{args.domain}/temp/shuffledns.tmp", "r")
        shuffledns_arr = f.read().rstrip().split("\n")
        for subdomain in shuffledns_arr:
            if args.domain not in subdomain and subdomain != "":
                i = shuffledns_arr.index(subdomain)
                del shuffledns_arr[i]
        f.close()
        subdomains_found = len(shuffledns_arr)
        print(f"[MSG] ShuffleDNS (Default) completed successfully: {subdomains_found} results found")
    except Exception as e:
        print(f"[!] Something went wrong!  Exception: {str(e)}")

def shuffle_dns_custom(args, home_dir):
    try:
        subprocess.run([f'echo {args.domain} | {home_dir}/go/bin/shuffledns -w wordlists/cewl_{args.domain}.txt -r wordlists/resolvers.txt -o {home_dir}/recon/data/{args.domain}/temp/shuffledns_custom.tmp'], shell=True)
        try:
            f = open(f"{home_dir}/recon/data/{args.domain}/temp/shuffledns_custom.tmp", "r")
        except:
            print("[!] No results found from the CeWL scan.  Skipping the 2nd round of ShuffleDNS...")
            return False
        shuffledns_custom_arr = f.read().rstrip().split("\n")
        f.close()
        clean_shuffledns_custom_arr = [item for item in shuffledns_custom_arr if item != ""]
        subdomains_found = len(clean_shuffledns_custom_arr)
        print(f"[MSG] ShuffleDNS (Custom) completed successfully: {subdomains_found} results found")
    except Exception as e:
        print(f"[!] ShuffleDNS w/ custom wordlist failed!\n[!] Exception: {str(e)}")

def naabu(args, home_dir):
    try:
        subprocess.run([f'{home_dir}/go/bin/naabu -l {home_dir}/recon/data/{args.domain}/temp/uniques.tmp -tp 100  -o {home_dir}/recon/data/{args.domain}/temp/naabu_ports.tmp'], shell=True)
        try:
            f = open(f"{home_dir}/recon/data/{args.domain}/temp/naabu_ports.tmp", "r")
        except:
            print("[!] No results found from the naabu port scan...")
            return False
        naabu_arr = f.read().rstrip().split("\n")
        f.close()
        naabu_arr = [item for item in naabu_arr if item != ""]
        subdomains_found = len(naabu_arr)
        text = f"Naabu completed successfully: {subdomains_found} results found."
        print(text)
    except Exception as e:
        print(f"[!] Naabu failed!\n[!] Exception: {str(e)}")

def httpx(args, home_dir):
    try:
        subprocess.run([f'{home_dir}/go/bin/httpx -l {home_dir}/recon/data/{args.domain}/temp/naabu_ports.tmp -t 500 -r wordlists/resolvers.txt -o {home_dir}/recon/data/{args.domain}/alive_subdomains.txt'], shell=True)
        try:
            f = open(f"{home_dir}/recon/data/{args.domain}/alive_subdomains.txt", "r")
        except:
            print("[!] No results found from the httpx scan...")
            return False
        httpx_arr = f.read().rstrip().split("\n")
        f.close()
        httpx_arr = [item for item in httpx_arr if item != ""]
        subdomains_found = len(httpx_arr)
        text_slack = f"Recon scan completed! \n\nTarget: *{args.domain}*. \nFound *{subdomains_found}* uniques subdomains. \n\nGood luck and happy hunting :D"
        text = f"Httpx completed successfully: {subdomains_found} results found."
        print(text)
        send_slack_notification(get_home_dir(), text_slack)
    except Exception as e:
        print(f"[!] httpx failed!\n[!] Exception: {str(e)}")


#################################### MAIN FUNCTION ####################################

def main(args):
    if check_dir() is False:
        create_dir()

    try:
        print(f"[-] Running Subfinder against {args.domain}")
        subfinder(args, get_home_dir())
    except Exception as e:
        print(f"[!] Exception: {e}")

    try:
        print(f"[-] Running Subfinder in Recursive Mode against {args.domain}")
        subfinder_recursive(args, get_home_dir())
    except Exception as e:
        print(f"[!] Exception: {e}")

    try:
        print(f"[-] Running Sublist3r against {args.domain}")
        sublist3r(args, get_home_dir())
    except Exception as e:
        print(f"[!] Exception: {e}")

    try:
        print(f"[-] Running Assetfinder against {args.domain}")
        assetfinder(args, get_home_dir())
    except Exception as e:
        print(f"[!] Exception: {e}")
    
    try:
        print(f"[-] Running GAU against {args.domain}")
        gau(args, get_home_dir())
    except Exception as e:
        print(f"[!] Exception: {e}")

    try:
        print(f"[-] Running CRT against {args.domain}")
        crt(args, get_home_dir())
    except Exception as e:
        print(f"[!] Exception: {e}")

    try:
        print(f"[-] Running Shuffle_dns against {args.domain}")
        shuffle_dns(args, get_home_dir())
    except Exception as e:
        print(f"[!] Exception: {e}")

    try:
        print(f"[-] Running recon on api's {args.domain}")
        apis(args, get_home_dir())
    except Exception as e:
        print(f"[!] Exception: {e}")

    try:
        print(f"[-] Running naabu against {args.domain}")
        sort_subdomains(get_home_dir(), args)
        naabu(args, get_home_dir())
    except Exception as e:
        print(f"[!] Exception: {e}")

    try:
        print(f"[-] Running httpx against {args.domain}")
        httpx(args, get_home_dir())
    except Exception as e:
        print(f"[!] Exception: {e}")

    cleanup(get_home_dir(), args)

if __name__ == "__main__":
    args = arg_parse()
    main(args)

