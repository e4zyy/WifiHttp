# WiFiHttp

WiFiHttp is a Python-based HTTP traffic analyzer created for network-security education and authorized lab testing. It uses Scapy to inspect unencrypted HTTP traffic and display basic request metadata.

> WARNING: Use this tool only on networks, systems, and devices that you own or are explicitly authorized to test. Unauthorized packet capture, credential interception, or cookie collection may violate privacy and computer-misuse laws.

## Features

- Lists available network interfaces.
- Attempts to identify an active Wi-Fi or network interface.
- Captures unencrypted HTTP traffic on TCP port 80.
- Displays HTTP request methods, URLs, IP addresses, ports, MAC addresses, and user-agent strings.
- Detects cookies present in HTTP request headers.
- Detects possible form fields such as usernames and passwords.
- Displays a summary when the capture is stopped.
- Saves captured request metadata to a timestamped text file.

## Important Security Notice

This tool can expose sensitive information when used on unencrypted HTTP traffic, including:

- Usernames.
- Passwords.
- Session cookies.
- URLs and request paths.
- IP addresses.
- MAC addresses.
- User-agent information.

Do not use this tool to monitor other people, public networks, workplaces, schools, hotels, cafés, or service-provider networks without clear written authorization.

For safer demonstrations, use:

- A private test network.
- Your own devices.
- Test accounts with non-sensitive passwords.
- A local HTTP server.
- Synthetic or prerecorded packet captures.
- Redaction of cookies, credentials, and POST bodies.

## Requirements

- Python 3.8 or newer.
- Linux is recommended.
- Root or administrator privileges may be required for packet capture.
- Scapy.
- Colorama.
- libpcap or an equivalent packet-capture backend.

## Installation

Create a virtual environment:

    python3 -m venv .venv

Activate it:

    source .venv/bin/activate

Install the Python dependencies:

    pip install scapy colorama

On Debian- or Ubuntu-based systems, install packet-capture support if required:

    sudo apt update
    sudo apt install libpcap-dev

## Usage

Run the analyzer:

    sudo python3 WifiHttp.py

Specify a network interface:

    sudo python3 WifiHttp.py --interface wlan0

The program captures traffic on TCP port 80 and displays matching HTTP requests.

Press Ctrl+C to stop the capture and display the summary.

## Example Output

    [*] Starting HTTP Sniffer on interface: wlan0
    [*] Capturing HTTP traffic... Press Ctrl+C to stop

    HTTP GET Request Captured
    Source IP: 192.168.1.20:51234
    Destination: 192.168.1.50:80
    URL: http://example.local/
    User-Agent: Example-Test-Client

## Output Files

When the capture stops, the program may create a file similar to:

    wifi_http_capture_20260825_193500.txt

The file can contain:

- Capture timestamps.
- Source and destination addresses.
- Source and destination ports.
- MAC addresses.
- HTTP methods.
- Requested URLs.
- User-agent strings.
- Cookie information.

Protect output files because they may contain sensitive network data.

## How It Works

The program uses Scapy to:

1. Detect available interfaces.
2. Select an active interface.
3. Capture packets using a TCP port 80 filter.
4. Identify HTTP request layers.
5. Extract request fields.
6. Process optional raw POST data.
7. Display and store selected information.

Scapy provides the packet-capture and packet-decoding functionality. WiFiHttp adds the application-specific logic for analyzing HTTP requests.

## HTTPS Limitation

WiFiHttp is intended for unencrypted HTTP traffic. It does not decrypt HTTPS traffic.

For HTTPS connections:

- The request body is encrypted.
- Passwords are not visible to a normal passive packet capture.
- Cookies and paths are generally protected by TLS.
- The tool may see encrypted TCP/TLS traffic but cannot interpret it as ordinary HTTP.

Do not attempt to bypass HTTPS protections or intercept traffic without explicit authorization.

## Legal and Ethical Use

You are responsible for complying with all applicable laws, regulations, contracts, and organizational policies.

Before using WiFiHttp, make sure that:

- You own or administer the network.
- You have written permission for the test.
- The test scope is clearly defined.
- Participants understand what data may be captured.
- Sensitive data is minimized and protected.
- Captured data is deleted after the exercise.
- Results are reported responsibly.

## Known Limitations

- The script is primarily designed for Linux environments.
- Packet-capture privileges may be required.
- It only filters TCP port 80 by default.
- It cannot normally inspect HTTPS contents.
- HTTP requests may be split across multiple TCP packets.
- POST data may not be complete when read from a single packet.
- Some HTTP fields may be absent and require additional error handling.
- Modern networks may redirect HTTP traffic to HTTPS.
- On switched networks, the host may not see all traffic.
- The interface-selection logic may override a manually supplied interface.
- The capture file may contain sensitive information.
- The program does not provide authentication, encryption, or secure log storage.

## Recommended Safety Improvements

Before using this project outside a controlled lab, consider:

- Removing password extraction.
- Redacting cookies and authorization headers.
- Never storing raw POST data.
- Saving only aggregate statistics.
- Encrypting or protecting output files.
- Adding a clear test-scope configuration.
- Adding input validation and exception handling.
- Supporting offline PCAP analysis instead of live capture.
- Adding a consent confirmation before starting capture.
- Automatically deleting sensitive temporary data.
- Using a dedicated test interface and isolated network.

## Development Status

This project is intended for educational use and authorized network-security testing. It should not be considered a production-grade monitoring, forensic, or intrusion-detection system.

## Responsible Disclosure

If you discover a security issue in this project, do not use it against systems that you do not own. Document the issue and report it privately to the project maintainer with reproduction details and suggested mitigations.

## License

MIT License by Xer0TLabs x Persephrak Decentralized Syndicate

## Disclaimer

The author is not responsible for misuse, damage, privacy violations, data loss, unauthorized monitoring, or legal consequences resulting from this software.

Use WiFiHttp only for lawful, authorized, and controlled security education.
