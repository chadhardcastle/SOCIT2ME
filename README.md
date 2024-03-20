# SOCIT2ME Multitool


The SOCIT2ME Multitool is a Python script built for SOC (Security Operations Center) Analysts, providing seamless threat intelligence lookup and QR code decoding capabilities. This tool is designed to assist cybersecurity professionals in gathering insights from various sources and efficiently extracting information from QR codes, all within a single application.

## Features

- Perform threat intelligence lookups for IP addresses, URLs/domains, and hash values.
- Decode QR codes from image files and retrieve embedded information.
- Access threat intelligence data from multiple sources including VirusTotal, URLScan, AbuseIPDB, IPQualityScore, and more.
- Launch sandboxes for URLs/domains using Browserling API to capture screenshots.

## Installation

1. Clone this repository to your local machine:

   ```bash
   git clone https://github.com/chadhardcastle/SOCIT2ME
   ```

2. Navigate to the project directory:

   ```bash
   cd SOCIT2ME-Multitool
   ```

3. Install the required Python packages:

   ```bash
   pip install -r requirements.txt
   ```

4. Create a `.env` file in the project directory and add your API keys:

   ```env
   API_KEY_VIRUSTOTAL=your_virustotal_api_key
   API_KEY_URLSCAN=your_urlscan_api_key
   API_KEY_IPQUALITYSCORE=your_ipqualityscore_api_key
   API_KEY_ABUSEIPDB=your_abuseipdb_api_key
   API_KEY_BROWSERLING=your_browserling_api_key
   ```

## Usage

Run the script `socit2me.py` and follow the prompts to enter the desired input:

```bash
python socit2me.py
```

- Enter an IP address, URL/domain, hash value, or provide a file path for QR code decoding.
- Type `exit` to exit the tool.
- Type `help` to display the help message.

## Example

```bash
Enter an IP address, URL/domain, hash value, or provide a file path for QR code decoding: 8.8.8.8
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request with any improvements or suggestions.

## License

This project is licensed under the [MIT License](LICENSE).
