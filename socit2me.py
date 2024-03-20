import os
from dotenv import load_dotenv
import re
import requests
from prettytable import PrettyTable
from colorama import Fore, Style
from pyzbar.pyzbar import decode
from PIL import Image

# Load environment variables from .env file
load_dotenv()

# Retrieve API keys from environment variables
API_KEY_VIRUSTOTAL = os.getenv("API_KEY_VIRUSTOTAL")
API_KEY_URLSCAN = os.getenv("API_KEY_URLSCAN")
API_KEY_IPQUALITYSCORE = os.getenv("API_KEY_IPQUALITYSCORE")
API_KEY_ABUSEIPDB = os.getenv("API_KEY_ABUSEIPDB")
API_KEY_CIRCL = os.getenv("API_KEY_CIRCL")
BROWSERLING_API_KEY = os.getenv("BROWSERLING_API_KEY")

print(f"""{Fore.CYAN}{Style.BRIGHT}
 _____  _____ _____ _____ _____ _____ ___  ___ _____ 
/  ___||  _  /  __ \_   _|_   _/ __  \|  \/  ||  ___|
\ `--. | | | | /  \/ | |   | | `' / /'| .  . || |__  
 `--. \| | | | |     | |   | |   / /  | |\/| ||  __| 
/\__/ /\ \_/ / \__/\_| |_  | | ./ /___| |  | || |___ 
\____/  \___/ \____/\___/  \_/ \_____/\_|  |_/\____/ 
                                                   {Style.RESET_ALL}""")

print(f"""The SOC Multitool - v1.1 - Created by{Fore.BLUE} https://github.com/chadhardcastle/
      {Style.RESET_ALL}""")

def decode_qr_from_file(image_path):
    try:
        img = Image.open(image_path)
        result = decode(img)
        if result:
            decoded_urls = [qr_result.data.decode("utf-8") for qr_result in result]
            return decoded_urls
        else:
            print("No QR code found in the image.")
            return []
    except Exception as e:
        print("Error:", e)
        return []

def identify_and_run(input_value):
    # Check if the input is a filename or path to decode a QR code
    if os.path.isfile(input_value):
        decoded_urls = decode_qr_from_file(input_value)
        if decoded_urls:
            for url in decoded_urls:
                identify_and_run(url)
        else:
            print("No valid QR code found in the image.")
    # Check if the input is an IP address
    elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", input_value):
        run_ip_functions(input_value)
    # Check if the input is a valid URL or domain
    elif re.match(r"^(https?://)?(www\.)?([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$", input_value):
        run_url_functions(input_value)
    # Check if the input is a valid hash value
    elif re.match(r"^[a-fA-F0-9]{32}$", input_value):
        run_hash_functions(input_value)
    elif re.match(r"^[a-fA-F0-9]{40}$", input_value):
        run_hash_functions(input_value)
    elif re.match(r"^[a-fA-F0-9]{64}$", input_value):
        run_hash_functions(input_value)
    elif re.match(r"^[a-fA-F0-9]{96}$", input_value):
        run_hash_functions(input_value)
    else:
        print("Invalid input.")



def run_ip_functions(ip_address):
    lookup_virustotal_ip(ip_address)
    lookup_abuseipdb(ip_address)
    lookup_ipqualityscore(ip_address)
    # Add other IP-related functions here

def run_url_functions(url):
    lookup_virustotal_url(url)
    lookup_urlscan(url)
    #lookup_browserling(url)
    # Add other URL-related functions here

def run_hash_functions(hash_value):
    lookup_virustotal_hash(hash_value)
    lookup_circl_hash(hash_value)
    # Add other hash-related functions here

def lookup_virustotal_ip(ip):
    print(f"""{Fore.CYAN}{Style.BRIGHT}
VirusTotal{Style.RESET_ALL}""")
    headers = {"x-apikey": API_KEY_VIRUSTOTAL}
    api_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    response = requests.get(api_url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        table = PrettyTable()
        table.field_names = ["Attribute", "Value"]
        table.add_row([f"{Style.BRIGHT}Community Score{Style.RESET_ALL}", data['data']['attributes']['reputation']])
        if 'last_analysis_stats' in data['data']['attributes']:
            table.add_row([f"{Style.BRIGHT}Vendor Score{Style.RESET_ALL}", data['data']['attributes']['last_analysis_stats']])
        table.add_row([f"{Style.BRIGHT}Report URL{Style.RESET_ALL}", f"{Fore.BLUE}https://www.virustotal.com/gui/ip-address/{ip}/detection{Style.RESET_ALL}"])
        print(table)
    else:
        print("Error:", response.text)

def lookup_virustotal_url(url):
    print(f"""{Fore.CYAN}{Style.BRIGHT}
VirusTotal{Style.RESET_ALL}""")
    headers = {"x-apikey": API_KEY_VIRUSTOTAL}
    api_url = f"https://www.virustotal.com/api/v3/search?query={url}"
    response = requests.get(api_url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        table = PrettyTable()
        table.field_names = ["Community Score", "Vendor Score", "Report URL"]
        for item in data["data"]:
            community_score = item["attributes"].get("reputation", "-")
            vendor_score = item["attributes"].get("last_analysis_stats", "-")
            report_url = f"{Fore.BLUE}https://www.virustotal.com/gui/domain/{item['id']}/detection{Style.RESET_ALL}"
            table.add_row([community_score, vendor_score, report_url])
        print(table)
    else:
        print("Error:", response.text)



def lookup_virustotal_hash(hash_value, hash_type):
    print(f"""{Fore.CYAN}{Style.BRIGHT}
VirusTotal{Style.RESET_ALL}""")
    if hash_type not in ["md5", "sha1", "sha256", "sha3-384"]:
        print("Invalid hash type. Supported types are: md5, sha1, sha256, sha3-384")
        return

    headers = {"x-apikey": API_KEY_VIRUSTOTAL}
    api_url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    response = requests.get(api_url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        table = PrettyTable()
        table.field_names = ["Attribute", "Value"]
        table.add_row(["Community Score", data['data']['attributes']['reputation']])
        if 'last_analysis_stats' in data['data']['attributes']:
            table.add_row(["Vendor Score", data['data']['attributes']['last_analysis_stats']])
        table.add_row(["Report URL", f"{Fore.BLUE}https://www.virustotal.com/gui/files/{hash_value}/detection{Style.RESET_ALL}"])
        print(table)
    else:
        print("Error:", response.text)

def lookup_abuseipdb(ip_address):
    print(f"""{Fore.CYAN}{Style.BRIGHT}
AbuseIPDB{Style.RESET_ALL}""")
    url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}'
    headers = {
        'Accept': 'application/json',
        'Key': API_KEY_ABUSEIPDB
    }

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        table = PrettyTable()
        table.field_names = ["Key", "Value"]
        for key, value in data['data'].items():
            table.add_row([key, str(value)])
        print(table)
    else:
        print("Error:", response.text)

def lookup_ipqualityscore(ip_address):
    print(f"""{Fore.CYAN}{Style.BRIGHT}
IPQualityScore{Style.RESET_ALL}""")
    url = f'https://www.ipqualityscore.com/api/json/ip/{API_KEY_IPQUALITYSCORE}/{ip_address}'
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        table = PrettyTable()
        table.field_names = ["Key", "Value"]
        for key, value in data.items():
            table.add_row([key, value])
        print(table)
    else:
        print("Error:", response.text)

def lookup_urlscan(url):
    print(f"""{Fore.CYAN}{Style.BRIGHT}
URLScan{Style.RESET_ALL}""")
    api_url = "https://urlscan.io/api/v1/scan/"
    headers = {"API-Key": API_KEY_URLSCAN}
    data = {"url": url}
    response = requests.post(api_url, headers=headers, json=data)
    if response.status_code == 200:
        result_url = response.json().get("result")
        if result_url:
            print(f"{Fore.CYAN}{Style.BRIGHT}URL Scan result:{Style.RESET_ALL} {result_url}")
        else:
            print(f"{Fore.RED}{Style.BRIGHT}No result found.{Style.RESET_ALL}")
    else:
        print("Error:", response.text)

def lookup_browserling(url):
    if not BROWSERLING_API_KEY:
        print("Browserling API key is not provided. Please add it to the .env file.")
        return

    api_url = f"https://api.browserling.com/v1/screenshots?token={BROWSERLING_API_KEY}&url={url}"
    response = requests.get(api_url)

    if response.status_code == 200:
        print("Sandbox launched successfully. You will receive the screenshot shortly.")
    else:
        print("Error launching sandbox:", response.text)

def lookup_circl_hash(hash_value, hash_type):
    print(f"""{Fore.CYAN}{Style.BRIGHT}
CIRCL{Style.RESET_ALL}""")
    api_url = f"https://hashlookup.circl.lu/lookup/{hash_type}/{hash_value}"
    headers = {'accept': 'application/json'}
    try:
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()
        data = response.json()
        table = PrettyTable()
        table.field_names = ['Key', 'Value']
        for key, value in data.items():
            table.add_row([key, value])
        print(table)
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

# Main function to run the script
def main():
    print(f"{Fore.BLUE}The SOCIT2ME Multitool is tailored for CyberSecurity professionals, offering seamless threat intelligence lookup and QR code decoding capabilities. With a user-friendly interface, analysts can swiftly gather insights from diverse sources and extract information from QR codes, all within a single tool. Streamlined workflow and customizable features enhance SOC efficiency, empowering analysts to respond promptly to security incidents and bolster threat detection efforts.{Style.RESET_ALL}\n") 
    print(f"To exit, type {Fore.RED}'exit'{Style.RESET_ALL}.")
    print(f"For help, type {Fore.GREEN}'help'{Style.RESET_ALL}.")
    while True:
        user_input = input(f"Enter an {Fore.YELLOW}IP address{Style.RESET_ALL}, {Fore.YELLOW}URL/domain{Style.RESET_ALL}, {Fore.YELLOW}hash value{Style.RESET_ALL}, or provide a {Fore.YELLOW}file path{Style.RESET_ALL} for QR code decoding: ").strip()
        if user_input.lower() == 'exit':
            print("Exiting the SOC Multitool. Goodbye!")
            break
        elif user_input.lower() == 'help':
            print_help()
        else:
            identify_and_run(user_input)



def print_help():
    print(f"{Fore.GREEN}SOCIT2ME Multitool Help{Style.RESET_ALL}")
    print("This tool allows you to perform the following actions:")
    print("- Enter an IP address, URL/domain, hash value, or file path to decode QR codes and perform threat intelligence lookups.")
    print("- Type 'exit' to exit the tool.")
    print("- Type 'help' to display this help message.")

# Entry point of the script
if __name__ == "__main__":
    main()
