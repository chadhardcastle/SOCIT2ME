import requests
import simplejson as json
import openai
from pyzbar.pyzbar import decode
from PIL import Image
from prettytable import PrettyTable
from colorama import init as colorama_init
from colorama import Fore
from colorama import Back
from colorama import Style

print(f"""{Fore.BLUE}{Style.BRIGHT}
 _____  _____ _____ _____ _____ _____ ___  ___ _____ 
/  ___||  _  /  __ \_   _|_   _/ __  \|  \/  ||  ___|
\ `--. | | | | /  \/ | |   | | `' / /'| .  . || |__  
 `--. \| | | | |     | |   | |   / /  | |\/| ||  __| 
/\__/ /\ \_/ / \__/\_| |_  | | ./ /___| |  | || |___ 
\____/  \___/ \____/\___/  \_/ \_____/\_|  |_/\____/ 
                                                   {Style.RESET_ALL}""")

print(f"""The SOC Multitool - Created by{Fore.BLUE} https://github.com/chadhardcastle/
      {Style.RESET_ALL}""")

def decode_qr():
    # Ask the user for the image file path
    print()
    image_path = input("Please enter the path to your image file: ")
    # Open the image file
    img = Image.open(image_path)
    # Decode the QR code
    result = decode(img)
    # Print the result
    for qr_result in result:
        decoded_url = qr_result.data.decode("utf-8")
        print(f"{Fore.CYAN}{Style.BRIGHT}Decoded text is: {Style.RESET_ALL}", decoded_url)
        lookup_url(decoded_url)

def lookup_url(url):
    # Define the API endpoint
    api_url = "https://urlscan.io/api/v1/scan/"
    # Define the headers with your API key
    headers = {
        "Content-Type": "application/json",
        "API-Key": "6cf53e1e-e087-4ced-84cb-cd5135355845"
    }
    # Define the data with the URL to scan
    data = {"url": url}
    # Make a POST request to the urlscan API
    response = requests.post(api_url, headers=headers, json=data)
    # Parse the JSON response
    data = response.json()
    # Extract and print the result URL
    result_url = data.get('result')
    if result_url:
        print(f"{Fore.CYAN}{Style.BRIGHT}URL lookup result: {Style.RESET_ALL}", result_url)

def get_ip_info(ip_address):
    print(f"""{Fore.CYAN}{Style.BRIGHT}
IPQualityScore{Style.RESET_ALL}""")
    api_key = 'yourapikeyhere'
    url = f'https://www.ipqualityscore.com/api/json/ip/{api_key}/{ip_address}'
    
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.json()
        table = PrettyTable()
        table.field_names = ["Key", "Value"]

        for key, value in data.items():
            table.add_row([key, value])

        print(table)

def get_abuse_info(ip_address):
    print(f"""{Fore.CYAN}{Style.BRIGHT}
AbuseIPDB{Style.RESET_ALL}""")
    api_key = '3725c29acc2a90007c713f1a24aa56e4f9f8667a1930d3d6edab82023a0e5aa0ac626953c3577e9c'
    url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}'
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }

    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        table = PrettyTable()
        table.field_names = ["Key", "Value"]

        for key, value in data['data'].items():
            table.add_row([key, str(value)])

        print(table)

def shodan_ip_search(ip_address):
    print(f"""{Fore.CYAN}{Style.BRIGHT}
SHODAN{Style.RESET_ALL}""")
    #def shodan_ip_search(ip_address):
    # Define the Shodan web search URL for the IP address
    search_url = f'https://www.shodan.io/host/{ip_address}'
    
    # Print the link to the Shodan web search results
    print(f"Here is the link to the Shodan web search results: {search_url}")

def lookup_ip(ip):
    print(f"""{Fore.CYAN}{Style.BRIGHT}
VirusTotal{Style.RESET_ALL}""")
    # Define the API endpoint
    api_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    # Define the headers with your API key
    headers = {
        "x-apikey": "64fd7895719b125d89103c1d65a1529c142190ca2f2ee3dc44e29b3a172a0243"
    }
    
    # Make a GET request to the VirusTotal API
    response = requests.get(api_url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        
        # Create a table to display some of the results
        table = PrettyTable()
        
        # Add columns to the table
        table.field_names = ["Attribute", "Value"]
        
        # Add some data to the table
        table.add_row([f"{Style.BRIGHT}Community Score{Style.RESET_ALL}", data['data']['attributes']['reputation']])
        if 'last_analysis_stats' in data['data']['attributes']:
            table.add_row([f"{Style.BRIGHT}Vendor Score{Style.RESET_ALL}", data['data']['attributes']['last_analysis_stats']])
        table.add_row([f"{Style.BRIGHT}Report URL{Style.RESET_ALL}", f"{Fore.BLUE}https://www.virustotal.com/gui/ip-address/{ip}/detection{Style.RESET_ALL}"])
        
        print(table)
        
        get_ip_info(ip)  # Call get_ip_info function here
        get_abuse_info(ip)  # Call get_abuse_info function here

def lookup_filehash(filehash):
    print(f"""{Fore.CYAN}{Style.BRIGHT}
VirusTotal{Style.RESET_ALL}""")
    # Define the API endpoint
    api_url = f"https://www.virustotal.com/api/v3/files/{filehash}"
    # Define the headers with your API key
    headers = {
        "x-apikey": "64fd7895719b125d89103c1d65a1529c142190ca2f2ee3dc44e29b3a172a0243"
    }
    
    # Make a GET request to the VirusTotal API
    response = requests.get(api_url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        
        # Create a table to display the results
        table = PrettyTable()
        
        # Add columns to the table
        table.field_names = ["Attribute", "Value"]
        
        # Add some data to the table
        table.add_row([f"{Style.BRIGHT}Community Score{Style.RESET_ALL}", data['data']['attributes']['reputation']])
        if 'last_analysis_stats' in data['data']['attributes']:
            table.add_row([f"{Style.BRIGHT}Vendor Score{Style.RESET_ALL}", data['data']['attributes']['last_analysis_stats']])
        table.add_row([f"{Style.BRIGHT}Report URL{Style.RESET_ALL}", f"{Fore.BLUE}https://www.virustotal.com/gui/files/{filehash}/detection{Style.RESET_ALL}"])
        
        print(table)

def lookup_hash(filehash):
    print(f"""{Fore.CYAN}{Style.BRIGHT}
CIRCL{Style.RESET_ALL}""")
    # Determine the hash type based on the length of the hash value
    if len(filehash) == 32:
        hash_type = "md5"
    elif len(filehash) == 40:
        hash_type = "sha1"
    elif len(filehash) == 64:
        hash_type = "sha256"
    else:
        print("Invalid hash value.")
        return

    # Define the API endpoint URL
    api_url = f'https://hashlookup.circl.lu/lookup/{hash_type}/{filehash}'
    
    # Define headers
    headers = {'accept': 'application/json'}
    
    try:
        # Make the API request
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()  # Raise an exception for HTTP errors
        
        # Parse the JSON response
        data = response.json()
        
        # Create a table for the results
        table = PrettyTable()
        table.field_names = ['Key', 'Value']
        
        # Add data to the table
        for key, value in data.items():
            table.add_row([key, value])
        
        # Print the table
        print(table)
        
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")



api_key = "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"
# Function to interact with ChatGPT
def chat_with_gpt():
    print()
    print("You are chatting with ChatGPT. Type 'exit' to end the conversation.\n")
    while True:
        user_input = input(f"{Fore.BLUE}{Style.BRIGHT}You: {Style.RESET_ALL}")
        if user_input.lower() == "exit":
            break

        response = ask_chat_gpt(user_input)
        print(f"{Fore.CYAN}{Style.BRIGHT}ChatGPT:{Style.RESET_ALL} {response}")

# Function to ask a question to ChatGPT
def ask_chat_gpt(question):
    response = openai.Completion.create(
        engine="text-davinci-002",
        prompt=f"You: {question}\nChatGPT:",
        max_tokens=150,  # Adjust as needed
        api_key=api_key
    )
    return response.choices[0].text.strip()


def main():
    while True:  # Add a loop to keep the user in the menu until they choose to exit
        print(f"""{Style.BRIGHT}Please select an option from below
              {Style.RESET_ALL}""")
        
        print("1. Decode QR code")
        print("2. Scan an IP address")
        print("3. Scan a Filehash")
        print("4. Ask ChatGPT")
        print("5. Exit")  # Add an option to exit
        
        choice = input(f"""{Style.BRIGHT}
What is your choice?: {Style.RESET_ALL}""")
        
        if choice == '1':
            decode_qr()
        elif choice == '2':
            print()
            ip_address = input(f"{Style.BRIGHT}Please enter an IP address: {Style.RESET_ALL}")
            lookup_ip(ip_address)
            shodan_ip_search(ip_address)
        elif choice == '3':
            print()
            filehash = input(f"{Style.BRIGHT}Please enter a filehash: {Style.RESET_ALL}")
            lookup_filehash(filehash)
            lookup_hash(filehash)
        elif choice == '4':
            chat_with_gpt()
        elif choice == '5':  # Exit the loop and the program
            break
        else:
            print("Invalid choice. Please select a valid option.")

        print()
        print(f"""{Fore.BLUE}{Style.BRIGHT}Would you like to choose another option? {Style.RESET_ALL}""")
        print()

        print("1. Decode QR code")
        print("2. Scan an IP address")
        print("3. Scan a Filehash")
        print("4. Ask ChatGPT")
        print("5. Exit")  # Add an option to exit
        
        choice = input(f"""{Style.BRIGHT}
What is your choice?: {Style.RESET_ALL}""")
        
        if choice == '1':
            decode_qr()
        elif choice == '2':
            print()
            ip_address = input(f"{Style.BRIGHT}Please enter an IP address: {Style.RESET_ALL}")
            lookup_ip(ip_address)
            shodan_ip_search(ip_address)
        elif choice == '3':
            print()
            filehash = input(f"{Style.BRIGHT}Please enter a filehash: {Style.RESET_ALL}")
            lookup_filehash(filehash)
            lookup_hash(filehash)
        elif choice == '4':
            chat_with_gpt()
        elif choice == '5':  # Exit the loop and the program
            break
        else:
            print()
            print(f"""{Fore.RED}{Style.BRIGHT}Invalid choice. Please select a valid option.{Style.RESET_ALL}""")
            print()

if __name__ == "__main__":
    main()