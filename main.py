import os
import subprocess
import requests
import whois
import socket
from bs4 import BeautifulSoup
import ssl
import dns.resolver
import dns.reversename
import dns.resolver
import ssl
import re
import requests
from urllib.parse import urlparse, urljoin

# Take user input for the target domain
target = input("Enter the target domain (e.g., example.com): ")
target_url = f"https://{target}"

def fetch_robots_txt(target_url):
    robots_url = urljoin(target_url, '/robots.txt')
    try:
        response = requests.get(robots_url)
        if response.status_code == 200:
            return response.text
        else:
            return None
    except Exception as e:
        print(f"Error fetching robots.txt: {str(e)}")
        return None

# Parse robots.txt to check which parts are off-limits
def parse_robots_txt(robots_txt):
    disallowed_paths = []
    if robots_txt:
        for line in robots_txt.split('\n'):
            if line.startswith('Disallow:'):
                parts = line.split(': ')
                if len(parts) >= 2:
                    path = parts[1]
                    disallowed_paths.append(path)
    return disallowed_paths


# Define the ports to scan
ports_to_scan = [80, 443, 22, 8080]


# Create a directory to store the gathered information
output_dir = os.path.join("bug_bounty_info", "target_info")
os.makedirs(output_dir, exist_ok=True)

def crawl_subdomains(target_url, visited_urls, output_file_path):
    try:
        # Send a GET request to the URL
        response = requests.get(target_url)
        visited_urls.add(target_url)

        # Parse the HTML content of the page
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all links on the page
        links = [link.get('href') for link in soup.find_all('a')]

        # Save the links to the output file
        with open(output_file_path, "w") as f:
            f.write("\n".join(links))
    except Exception as e:
        print(f"Error while crawling {target_url}: {str(e)}")

# Call the crawl_subdomains function with the 'target_url' and specify the output file path.
output_file_path = os.path.join(output_dir, "web_links.txt")
crawl_subdomains(target_url, set(), output_file_path)

def perform_dns_enumeration(target, output_dir):
    pass

# Step 1: Whois Lookup
whois_info = whois.whois(target)
with open(os.path.join(output_dir, "whois_info.txt"), "w") as f:
    f.write(str(whois_info))

# Step 2: DNS Enumeration
dns_resolver = dns.resolver.Resolver()

# Query A records (IPv4 addresses)
a_records = dns_resolver.resolve(target, "A")
with open(os.path.join(output_dir, "a_records.txt"), "w") as a_file:
    a_file.write("\n".join(str(record) for record in a_records))

# Query MX records (Mail Exchanges)
try:
    mx_records = dns_resolver.resolve(target, "MX")
    with open(os.path.join(output_dir, "mx_records.txt"), "w") as mx_file:
        mx_file.write("\n".join(str(record) for record in mx_records))
except dns.resolver.NoAnswer:
    with open(os.path.join(output_dir, "mx_records.txt"), "w") as mx_file:
        mx_file.write("No MX records found for the target domain.")

# Query NS records (Name Servers)
ns_records = dns_resolver.resolve(target, "NS")
with open(os.path.join(output_dir, "ns_records.txt"), "w") as ns_file:
    ns_file.write("\n".join(str(record) for record in ns_records))

try:
    # Query CNAME records (Canonical Name)
    cname_records = dns_resolver.resolve(target, "CNAME")
    with open(os.path.join(output_dir, "cname_records.txt"), "w") as cname_file:
        cname_file.write("\n".join(str(record) for record in cname_records))
except dns.resolver.NoAnswer:
    with open(os.path.join(output_dir, "cname_records.txt"), "w") as cname_file:
        cname_file.write("No CNAME records found for the target domain.")



# Step 3: Port Scanning
def scan_ports(target_host, ports):
    open_ports = []

    for port in ports:
        try:
            # Create a socket object
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Set a timeout for the connection attempt (in seconds)
            socket.setdefaulttimeout(1)

            # Attempt to connect to the target host and port
            result = client_socket.connect_ex((target_host, port))

            # Check if the connection was successful
            if result == 0:
                print(f"Port {port} is open")
                open_ports.append(port)

            # Close the socket
            client_socket.close()

        except KeyboardInterrupt:
            print("Port scanning stopped by user.")
            break

        except Exception as e:
            print(f"Error scanning port {port}: {str(e)}")

    return open_ports

# Perform the port scan
open_ports = scan_ports(target, ports_to_scan)  # Use 'target' instead of 'target_host'

# Print the list of open ports
if open_ports:
    print("Open ports:", open_ports)
else:
    print("No open ports found on the target host.")

# Step 4: SSL Certificate Analysis
try:
    cert = ssl.get_server_certificate((target, 443))
    with open(os.path.join(output_dir, "ssl_certificate.pem"), "w") as f:
        f.write(cert)
except Exception as e:
    pass

# Step 5: Web Crawling
def crawl_subdomains(target_url, visited_urls, output_file):
    try:
        # Send a GET request to the URL
        response = requests.get(target_url)
        visited_urls.add(target_url)

        # Parse the HTML content of the page
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all links on the page
        links = [link.get('href') for link in soup.find_all('a')]

        # Save the links to the output file
        with open(output_file, "w") as f:
            f.write("\n".join(links))
    except Exception as e:
        print(f"Error while crawling {target_url}: {str(e)}")

# Step 6: Content Discovery
def discover_links(url, visited_links):
    # Limit the depth of crawling to avoid infinite loops
    if len(visited_links) > 250:
        return

    try:
        # Send a GET request to the URL
        response = requests.get(url)

        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            # Parse the HTML content of the page
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find all links on the page
            links = [link.get('href') for link in soup.find_all('a')]

            # Save the links to a file
            with open(os.path.join(output_dir, 'discovered_links.txt'), 'a') as f:
                for link in links:
                    f.write(link + '\n')

            # Recursively discover links on linked pages
            for link in links:
                if link and link not in visited_links:
                    visited_links.add(link)
                    new_url = urljoin(url, link)  # You may need to import urljoin from urllib.parse
                    discover_links(new_url, visited_links)
    except Exception as e:
        pass  # Handle exceptions, e.g., connection errors

# Initialize a list to store detected vulnerabilities
vulnerabilities_file = os.path.join(output_dir, "vulnerabilities.txt")
detected_vulnerabilities = []

# Step 7 Part 1: Vulnerabilities Testing
def test_vulnerabilities(target_url, detected_vulnerabilities):
    # SQL Injection Test
    sql_injection_payload = "admin' OR 1=1 --"
    response = requests.get(target_url + f"/login?username={sql_injection_payload}&password=password")

    if "Welcome, admin" in response.text:
        detected_vulnerabilities.append({
            "Vulnerability": "SQL Injection",
            "Payload": sql_injection_payload,
            "URL Parameter": "/login",
            "Description": "Possible SQL Injection detected"
        })

    # Cross-Site Scripting (XSS) Test
    xss_payload = "<script>alert('XSS')</script>"
    response = requests.get(target_url + f"/search?q={xss_payload}")

    if "<script>alert('XSS')</script>" in response.text:
        detected_vulnerabilities.append({
            "Vulnerability": "XSS",
            "Payload": xss_payload,
            "URL Parameter": "/search?q=" + xss_payload,
            "Description": "Possible XSS vulnerability detected"
        })

    # Local File Inclusion (LFI) Test
    lfi_payload = "../../../../etc/passwd"
    response = requests.get(target_url + f"/?file={lfi_payload}")

    if "root:x:0:0" in response.text:
        detected_vulnerabilities.append({
            "Vulnerability": "Local File Inclusion",
            "Payload": lfi_payload,
            "URL Parameter": f"/?file={lfi_payload}",
            "Description": "Possible LFI vulnerability detected"
        })

    # Remote Code Execution (RCE) Test
    rce_payload = "; ls -la"
    response = requests.get(target_url + f"/?param={rce_payload}")

    if "file1.txt" in response.text:
        detected_vulnerabilities.append({
            "Vulnerability": "Remote Code Execution (RCE)",
            "Payload": rce_payload,
            "URL Parameter": f"/?param={rce_payload}",
            "Description": "Possible RCE vulnerability detected"
        })

    # URL Redirect Test
    url_redirect_payload = "https://quillbot.com/"
    response = requests.get(target_url + f"/redirect?target={url_redirect_payload}")

    if "Location: https://quillbot.com/" in response.headers:
        detected_vulnerabilities.append({
            "Vulnerability": "URL Redirect",
            "Payload": url_redirect_payload,
            "URL Parameter": f"/redirect?target={url_redirect_payload}",
            "Description": "Possible URL Redirect vulnerability detected"
        })

    # Server-Side Request Forgery (SSRF) Test
    ssrf_payload = "http://internal-server/admin"
    response = requests.get(target_url + f"/endpoint?target={ssrf_payload}")

    if "Admin Page" in response.text:
        detected_vulnerabilities.append({
            "Vulnerability": "Server-Side Request Forgery (SSRF)",
            "Payload": ssrf_payload,
            "URL Parameter": f"/endpoint?target={ssrf_payload}",
            "Description": "Possible SSRF vulnerability detected"
        })

    # Server-Side Template Injection (SSTI) Test
    ssti_payload = "{{7*7}}"
    response = requests.get(target_url + f"/profile?name={ssti_payload}")

    if "49" in response.text:
        detected_vulnerabilities.append({
            "Vulnerability": "Server-Side Template Injection (SSTI)",
            "Payload": ssti_payload,
            "URL Parameter": f"/profile?name={ssti_payload}",
            "Description": "Possible SSTI vulnerability detected"
        })

    # Broken Authentication/Session Management Test
    session = requests.Session()
    login_payload = {"username": "admin", "password": "password"}
    login_response = session.post(target_url + "/login", data=login_payload)

    profile_response = session.get(target_url + "/profile?user=other_user")

    if "Other User's Profile" in profile_response.text:
        detected_vulnerabilities.append({
            "Vulnerability": "Broken Authentication/Session Management",
            "Payload": None,
            "URL Parameter": "/profile?user=other_user",
            "Description": "Possible Broken Authentication/Session Management vulnerability detected"
        })

    # Insecure Deserialization Test
    insecure_deserialization_payload = {"data": "H4sIAAAAAAAA/8tJLS5RsjPLTCopy/OT8lM3JxOHKwIA=="}
    response = requests.post(target_url + "/deserialize", json=insecure_deserialization_payload)

    if "Welcome, admin" in response.text:
        detected_vulnerabilities.append({
            "Vulnerability": "Insecure Deserialization",
            "Payload": insecure_deserialization_payload,
            "URL Parameter": "/deserialize",
            "Description": "Possible Insecure Deserialization vulnerability detected"
        })

    # Sensitive Data Exposure Test
    response = requests.get(target_url + "/api/customer/12345")

    # Define regular expressions to match sensitive data patterns
    password_pattern = re.compile(r"(?i)(password|passwd|pwd)[:=]\s*(\w+)")
    username_pattern = re.compile(r"(?i)(username|user)[:=]\s*(\w+)")
    email_pattern = re.compile(r"(?i)(email)[:=]\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4})")
    name_pattern = re.compile(r"(?i)(name)[:=]\s*(\w+)")

    # Search for sensitive data patterns in the response text
    sensitive_data = []

    # Check for passwords
    password_matches = password_pattern.findall(response.text)
    if password_matches:
        for match in password_matches:
            if match[1].lower() not in ["password", "passwd", "pwd"]:
                sensitive_data.append({"Type": match[0], "Value": match[1]})

    # Check for usernames
    username_matches = username_pattern.findall(response.text)
    if username_matches:
        for match in username_matches:
            if match[1].lower() not in ["username", "user"]:
                sensitive_data.append({"Type": match[0], "Value": match[1]})

    # Check for email addresses
    email_matches = email_pattern.findall(response.text)
    if email_matches:
        for match in email_matches:
            sensitive_data.append({"Type": match[0], "Value": match[1]})

    # Check for names
    name_matches = name_pattern.findall(response.text)
    if name_matches:
        for match in name_matches:
            if match[1].lower() not in ["name"]:
                sensitive_data.append({"Type": match[0], "Value": match[1]})

    # If sensitive data is found, add it to detected vulnerabilities
    if sensitive_data:
        detected_vulnerabilities.append({
            "Vulnerability": "Sensitive Data Exposure",
            "Payload": None,
            "URL Parameter": None,
            "Description": "Possible Sensitive Data Exposure vulnerabilities detected",
            "Sensitive Data": sensitive_data
        })

# Call the vulnerability testing function
test_vulnerabilities(target_url, detected_vulnerabilities)


# Open the "Vulnerabilities.txt" file for writing
with open(os.path.join(output_dir, "Vulnerabilities.txt"), "w") as f:
    # Iterate over detected vulnerabilities and write each one to the text file
    for vulnerability in detected_vulnerabilities:
        f.write("Vulnerability:\n")
        if 'Full URL with Payload' in vulnerability:
            f.write(f"  Full URL with Payload: {vulnerability['Full URL with Payload']}\n")
        for vulnerability in detected_vulnerabilities:
            if vulnerability.get('Payload'):
                f.write(f"  Payload: {vulnerability['Payload']}\n")
        if vulnerability.get('URL Parameter'):
            f.write(f"  URL Parameter: {vulnerability['URL Parameter']}\n")
        f.write(f"  Description: {vulnerability['Description']}\n")
        f.write("---------------------------------------------------\n")


# Step 7 Part 2
from pycvesearch import CVESearch
software_list = ["Apache Tomcat", "WordPress", "NGINX", "MySQL", "Node.js"]

# Initialize a dictionary to store CVE results for each software or technology
cve_results_dict = {}

# Create an instance of the CVESearch class with the base URL
base_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"

# Loop through the software list and perform CVE lookups
for software_name in software_list:
    # Create the API URL to fetch CVE data for a specific product (replace spaces with %20)
    api_url = f"{base_url}?keyword={software_name.replace(' ', '%20')}"

    # Send a GET request to the NVD API
    response = requests.get(api_url)

    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        cve_results = response.json().get("result", {}).get("CVE_Items", [])
        cve_results_dict[software_name] = cve_results
    else:
        cve_results_dict[software_name] = []

# Check if any CVEs were found for any software or technology
cve_found = any(cve_results for cve_results in cve_results_dict.values())

# Open the "Vulnerabilities.txt" file for writing
with open("Vulnerabilities.txt", "w") as f:
    # Iterate over detected vulnerabilities and write each one to the text file
    for software_name, cve_results in cve_results_dict.items():
        f.write(f"CVEs related to {software_name}:\n")
        if cve_results:
            for cve in cve_results:
                cve_id = cve['cve']['CVE_data_meta']['ID']
                description = cve['cve']['description']['description_data'][0]['value']
                cvss_v3 = "N/A"  # You can extract the CVSS score from the JSON response

                f.write(f"  CVE ID: {cve_id}\n")
                f.write(f"  Description: {description}\n")
                f.write(f"  CVSS Score (v3): {cvss_v3}\n\n")
        else:
            f.write(f"No CVEs related to {software_name} found.\n")

print("Vulnerabilities have been written to 'Vulnerabilities.txt'.")

# Step 8: Technology Stack Identification
headers = response.headers
server = headers.get("Server", "")
with open(os.path.join(output_dir, "server_info.txt"), "w") as f:
    f.write(server)



# Step 11: Email Harvesting
def extract_emails_from_text(text):
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
    return re.findall(email_pattern, text)

# Function to crawl and harvest email addresses
def crawl_and_harvest_emails(start_url, max_depth=5):
    visited_urls = set()
    email_addresses = set()

    def crawl(url, depth):
        if depth > max_depth or url in visited_urls:
            return
        visited_urls.add(url)

        try:
            response = requests.get(url)
            if response.status_code == 200:
                text = response.text
                new_emails = extract_emails_from_text(text)
                email_addresses.update(new_emails)

                soup = BeautifulSoup(text, 'html.parser')

                # Extract links from the page and crawl them
                links = [a['href'] for a in soup.find_all('a', href=True)]
                for link in links:
                    absolute_url = urljoin(url, link)
                    if urlparse(absolute_url).netloc == urlparse(start_url).netloc:
                        crawl(absolute_url, depth + 1)
        except Exception as e:
            print(f"Error while crawling {url}: {str(e)}")

    crawl(start_url, depth=100)

    # Print and/or save the harvested email addresses
    for email in email_addresses:
        print("Email:", email)
    target_url = f"https://{target}"
    crawl_and_harvest_emails(start_url)

# Step 12: Social Media Research (OSINT)
# You can customize this step based on your target and needs.
# Example: Search for the target organization on various social media platforms.
social_media_platforms = ["twitter", "facebook", "linkedin", "instagram"]
for platform in social_media_platforms:
    search_query = f"site:{platform}.com {target}"
    # Perform OSINT search on the specific platform and save the results.


# Step 14: API Endpoint Discovery (Automatic)
# Automatically identify and test API endpoints

# Initialize a list to store discovered endpoints
discovered_endpoints = []
api_endpoints = [
    "api",
    "v1",
    "v2",
    "rest",
    "graphql",
    "public",
    "private",
    "secure",
    "auth",
    "admin",
    "user",
    "customer",
    "order",
    "product",
    "payment",
    "cart",
    "account",
    "profile",
    "notification",
    "settings",
    "search",
    "blog",
    "forum",
    "comment",
    "feedback",
    "feedbacks",
    "feedbacklist",
    "reviews",
    "message",
    "chat",
    "chatroom",
    "conversation",
    "inbox",
    "outbox",
    "messages",
    "mail",
    "mailbox",
    "subscribe",
    "unsubscribe",
    "follow",
    "unfollow",
    "like",
    "dislike",
    "favorite",
    "bookmark",
    "upload",
    "download",
    "file",
    "image",
    "video",
    "media",
    "content",
    "post",
    "create",
    "update",
    "delete",
    "remove",
    "edit",
    "change",
    "manage",
    "process",
    "request",
    "submit",
    "verify",
    "reset",
    "password",
    "token",
    "auth",
    "login",
    "logout",
    "register",
    "signup",
    "signin",
    "signout",
    "user",
    "users",
    "account",
    "profile",
    "dashboard",
    "home",
    "index",
    "about",
    "contact",
    "help",
    "faq",
    "support",
    "terms",
    "privacy",
    "policy",
    "legal",
    "info",
    "news",
    "newsletter",
    "subscribe",
    "unsubscribe",
    "feed",
    "rss",
    "xml",
    "json",
    "jsonp",
    "atom",
    "status",
    "ping",
    "health",
    "check",
    "test",
    "echo",
    "version",
    "info",
    "debug",
    "metrics",
    "stats",
    "data",
    "analytics",
    "insights",
    "report",
    "logs",
    "log",
    "audit",
    "history",
    "backup",
    "restore",
    "sync",
    "cron",
    "schedule",
    "task",
    "job",
    "queue",
    "worker",
    "notification",
    "notify",
    "alert",
    "push",
    "email",
    "sms",
    "messaging",
    "chat",
    "message",
    "notification",
    "notify",
    "alert",
    "push",
    "email",
    "sms",
    "messaging",
    "chat",
    "message",
    "notification",
    "notify",
    "alert",
    "push",
    "email",
    "sms",
    "messaging",
    "chat",
    "message",
    "notification",
    "notify",
    "alert",
    "push",
    "email",
    "sms",
    "messaging",
    "chat",
    "message",
]

# Generate potential API endpoint URLs
for endpoint in api_endpoints:
    api_url = f"{target}/{endpoint}"
    discovered_endpoints.append(api_url)

# Test the discovered endpoints (e.g., send requests and analyze responses)
for endpoint in discovered_endpoints:
    # Send requests and analyze responses for each endpoint
    pass

# Save the list of discovered endpoints to a file
with open(os.path.join(output_dir, "api_endpoints.txt"), "w") as f:
    f.write("\n".join(discovered_endpoints))

print("The scan and information gathering process is complete. Results are saved in the 'bug_bounty_info' directory.")