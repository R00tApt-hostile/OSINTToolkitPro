import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import webbrowser
import socket
import requests
import json
import dns.resolver
import whois
import re
from ipwhois import IPWhois
import phonenumbers
from PIL import Image, ImageTk
import io
import os
import subprocess
import platform
import hashlib
import base64
from datetime import datetime

class OSINTToolkit:
    def __init__(self, root):
        self.root = root
        self.root.title("OSINT Toolkit Pro")
        self.root.geometry("1200x800")
        
        # API configuration
        self.api_config = {
            "hibp_api_key": "",  # Add your HIBP API key here
            "virustotal_api_key": "",  # Add your VirusTotal API key here
            "shodan_api_key": ""  # Optional: Add Shodan API key
        }
        
        # Load API keys from config file if exists
        self.load_api_config()
        
        # Style configuration
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Color themes
        self.themes = {
            "Dark": {
                "bg": "#2d2d2d",
                "fg": "#ffffff",
                "accent": "#4a90d9",
                "secondary": "#3d3d3d"
            },
            "Light": {
                "bg": "#f5f5f5",
                "fg": "#000000",
                "accent": "#4a90d9",
                "secondary": "#e0e0e0"
            },
            "Blue": {
                "bg": "#1c3f6e",
                "fg": "#ffffff",
                "accent": "#4a90d9",
                "secondary": "#2a4f7d"
            },
            "Green": {
                "bg": "#2d4d2d",
                "fg": "#ffffff",
                "accent": "#4ad94a",
                "secondary": "#3d5d3d"
            }
        }
        
        self.current_theme = "Dark"
        self.apply_theme()
        
        # Create menu
        self.create_menu()
        
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.create_domain_tab()
        self.create_ip_tab()
        self.create_email_tab()
        self.create_phone_tab()
        self.create_person_tab()
        self.create_social_tab()
        self.create_image_tab()
        self.create_metadata_tab()
        self.create_dns_tab()
        self.create_whois_tab()
        self.create_breach_tab()
        self.create_geo_tab()
        self.create_network_tab()
        self.create_username_tab()
        self.create_web_tab()
        self.create_virustotal_tab()  # New tab for VirusTotal
        self.create_settings_tab()  # New tab for API settings
        
        # Status bar
        self.status = tk.Label(root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status.pack(side=tk.BOTTOM, fill=tk.X)
    
    def load_api_config(self):
        try:
            if os.path.exists("osint_config.json"):
                with open("osint_config.json", "r") as f:
                    config = json.load(f)
                    self.api_config.update(config)
        except Exception as e:
            print(f"Error loading config: {e}")
    
    def save_api_config(self):
        try:
            with open("osint_config.json", "w") as f:
                json.dump(self.api_config, f)
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def apply_theme(self):
        theme = self.themes[self.current_theme]
        self.root.config(bg=theme["bg"])
        self.style.configure(".", background=theme["bg"], foreground=theme["fg"])
        self.style.configure("TNotebook", background=theme["secondary"])
        self.style.configure("TNotebook.Tab", background=theme["secondary"], foreground=theme["fg"])
        self.style.map("TNotebook.Tab", background=[("selected", theme["accent"])])
        self.style.configure("TFrame", background=theme["bg"])
        self.style.configure("TLabel", background=theme["bg"], foreground=theme["fg"])
        self.style.configure("TButton", background=theme["accent"], foreground=theme["fg"])
        self.style.configure("TEntry", fieldbackground=theme["secondary"], foreground=theme["fg"])
        self.style.configure("TCombobox", fieldbackground=theme["secondary"], foreground=theme["fg"])
        self.style.configure("TScrollbar", background=theme["secondary"])
    
    def create_menu(self):
        menubar = tk.Menu(self.root)
        
        # Theme menu
        theme_menu = tk.Menu(menubar, tearoff=0)
        for theme_name in self.themes:
            theme_menu.add_command(label=theme_name, command=lambda n=theme_name: self.change_theme(n))
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Check API Status", command=self.check_api_status)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        
        menubar.add_cascade(label="Themes", menu=theme_menu)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def change_theme(self, theme_name):
        self.current_theme = theme_name
        self.apply_theme()
    
    def show_about(self):
        about_text = """OSINT Toolkit Pro v2.0
        
A comprehensive Open Source Intelligence toolkit with API integrations.

Features include:
- Domain information with VirusTotal integration
- IP analysis with Shodan integration
- Email verification with HaveIBeenPwned
- Phone number lookup
- Person search
- Social media search
- Image analysis
- Metadata extraction
- DNS lookup
- WHOIS lookup
- Breach check with HIBP API
- Geolocation
- Network tools
- Username search
- Web utilities
- VirusTotal scans"""
        messagebox.showinfo("About OSINT Toolkit Pro", about_text)
    
    def check_api_status(self):
        status = []
        
        # Check HIBP API
        hibp_status = "HIBP API: "
        if self.api_config["hibp_api_key"]:
            try:
                headers = {"hibp-api-key": self.api_config["hibp_api_key"]}
                response = requests.get("https://haveibeenpwned.com/api/v3/breaches", headers=headers)
                if response.status_code == 200:
                    hibp_status += "✔️ Working"
                else:
                    hibp_status += f"❌ Error (HTTP {response.status_code})"
            except Exception as e:
                hibp_status += f"❌ Connection failed: {str(e)}"
        else:
            hibp_status += "❌ Not configured"
        status.append(hibp_status)
        
        # Check VirusTotal API
        vt_status = "VirusTotal API: "
        if self.api_config["virustotal_api_key"]:
            try:
                params = {"apikey": self.api_config["virustotal_api_key"], "resource": "example.com"}
                response = requests.get("https://www.virustotal.com/vtapi/v2/url/report", params=params)
                if response.status_code == 200:
                    vt_status += "✔️ Working"
                elif response.status_code == 204:
                    vt_status += "⚠️ API limit reached"
                else:
                    vt_status += f"❌ Error (HTTP {response.status_code})"
            except Exception as e:
                vt_status += f"❌ Connection failed: {str(e)}"
        else:
            vt_status += "❌ Not configured"
        status.append(vt_status)
        
        messagebox.showinfo("API Status", "\n".join(status))
    
    def update_status(self, message):
        self.status.config(text=message)
        self.root.update_idletasks()
    
    # New tab for VirusTotal
    def create_virustotal_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="VirusTotal")
        
        frame = ttk.Frame(tab)
        frame.pack(pady=10, padx=10, fill=tk.X)
        
        ttk.Label(frame, text="Scan Target:").pack(side=tk.LEFT)
        self.vt_entry = ttk.Entry(frame, width=40)
        self.vt_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(frame, text="Type:").pack(side=tk.LEFT)
        self.vt_type = ttk.Combobox(frame, values=["URL", "Domain", "IP", "File Hash"], width=12)
        self.vt_type.current(0)
        self.vt_type.pack(side=tk.LEFT, padx=5)
        
        btn = ttk.Button(frame, text="Scan", command=self.virustotal_scan)
        btn.pack(side=tk.LEFT)
        
        self.vt_output = scrolledtext.ScrolledText(tab, width=120, height=30)
        self.vt_output.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
    
    # New tab for API settings
    def create_settings_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Settings")
        
        # API Keys Frame
        api_frame = ttk.LabelFrame(tab, text="API Keys")
        api_frame.pack(pady=10, padx=10, fill=tk.X)
        
        # HIBP API
        ttk.Label(api_frame, text="HaveIBeenPwned API Key:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.hibp_api_entry = ttk.Entry(api_frame, width=50)
        self.hibp_api_entry.grid(row=0, column=1, padx=5, pady=5)
        self.hibp_api_entry.insert(0, self.api_config["hibp_api_key"])
        
        # VirusTotal API
        ttk.Label(api_frame, text="VirusTotal API Key:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.vt_api_entry = ttk.Entry(api_frame, width=50)
        self.vt_api_entry.grid(row=1, column=1, padx=5, pady=5)
        self.vt_api_entry.insert(0, self.api_config["virustotal_api_key"])
        
        # Shodan API
        ttk.Label(api_frame, text="Shodan API Key:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.shodan_api_entry = ttk.Entry(api_frame, width=50)
        self.shodan_api_entry.grid(row=2, column=1, padx=5, pady=5)
        self.shodan_api_entry.insert(0, self.api_config["shodan_api_key"])
        
        # Save Button
        save_btn = ttk.Button(api_frame, text="Save API Keys", command=self.save_api_keys)
        save_btn.grid(row=3, column=1, pady=10, sticky=tk.E)
    
    def save_api_keys(self):
        self.api_config["hibp_api_key"] = self.hibp_api_entry.get().strip()
        self.api_config["virustotal_api_key"] = self.vt_api_entry.get().strip()
        self.api_config["shodan_api_key"] = self.shodan_api_entry.get().strip()
        self.save_api_config()
        messagebox.showinfo("Success", "API keys saved successfully!")
    
    # Enhanced breach check with HIBP API
    def check_breach(self):
        query = self.breach_entry.get().strip()
        if not query:
            messagebox.showerror("Error", "Please enter an email or username")
            return
        
        self.update_status(f"Checking breaches for: {query}...")
        self.breach_output.delete(1.0, tk.END)
        
        try:
            self.breach_output.insert(tk.END, f"=== Breach Check: {query} ===\n\n")
            
            # Check if it's an email or username
            is_email = "@" in query
            
            if is_email:
                # Check breaches using HIBP API if key is available
                if self.api_config["hibp_api_key"]:
                    self.breach_output.insert(tk.END, "Checking HaveIBeenPwned database...\n\n")
                    
                    headers = {"hibp-api-key": self.api_config["hibp_api_key"]}
                    try:
                        # Check breaches
                        breach_url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{query}?truncateResponse=false"
                        response = requests.get(breach_url, headers=headers)
                        
                        if response.status_code == 200:
                            breaches = response.json()
                            self.breach_output.insert(tk.END, f"Found in {len(breaches)} breaches:\n\n")
                            for breach in breaches:
                                self.breach_output.insert(tk.END, f"Name: {breach['Name']}\n")
                                self.breach_output.insert(tk.END, f"Domain: {breach['Domain']}\n")
                                self.breach_output.insert(tk.END, f"Date: {breach['BreachDate']}\n")
                                self.breach_output.insert(tk.END, f"Compromised Data: {', '.join(breach['DataClasses'])}\n")
                                self.breach_output.insert(tk.END, f"Description: {breach['Description']}\n")
                                self.breach_output.insert(tk.END, "-" * 50 + "\n")
                        elif response.status_code == 404:
                            self.breach_output.insert(tk.END, "No breaches found for this email\n")
                        else:
                            self.breach_output.insert(tk.END, f"Error checking breaches: HTTP {response.status_code}\n")
                        
                        # Check pastes
                        self.breach_output.insert(tk.END, "\nChecking pastebin dumps...\n\n")
                        paste_url = f"https://haveibeenpwned.com/api/v3/pasteaccount/{query}"
                        response = requests.get(paste_url, headers=headers)
                        
                        if response.status_code == 200:
                            pastes = response.json()
                            if pastes:
                                self.breach_output.insert(tk.END, f"Found in {len(pastes)} pastebin dumps:\n\n")
                                for paste in pastes:
                                    self.breach_output.insert(tk.END, f"Source: {paste['Source']}\n")
                                    self.breach_output.insert(tk.END, f"ID: {paste['Id']}\n")
                                    self.breach_output.insert(tk.END, f"Title: {paste['Title']}\n")
                                    self.breach_output.insert(tk.END, f"Date: {paste['Date']}\n")
                                    self.breach_output.insert(tk.END, f"Email Count: {paste['EmailCount']}\n")
                                    self.breach_output.insert(tk.END, "-" * 50 + "\n")
                            else:
                                self.breach_output.insert(tk.END, "No pastebin dumps found\n")
                        elif response.status_code != 404:
                            self.breach_output.insert(tk.END, f"Error checking pastes: HTTP {response.status_code}\n")
                    except Exception as e:
                        self.breach_output.insert(tk.END, f"API request failed: {str(e)}\n")
                else:
                    self.breach_output.insert(tk.END, "HIBP API key not configured. Using fallback method.\n")
            
            # Fallback to links if no API key or for usernames
            self.breach_output.insert(tk.END, "\nBreach Check Links:\n")
            self.breach_output.insert(tk.END, f"Have I Been Pwned: https://haveibeenpwned.com/unifiedsearch/{query}\n")
            self.breach_output.insert(tk.END, f"DeHashed: https://www.dehashed.com/search?query={query}\n")
            self.breach_output.insert(tk.END, f"LeakCheck: https://leakcheck.io/search?query={query}\n")
            self.breach_output.insert(tk.END, f"Snusbase: https://snusbase.com/\n")
            self.breach_output.insert(tk.END, f"WeLeakInfo: https://weleakinfo.com/\n")
            
            self.update_status(f"Breach check complete: {query}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to check breaches: {str(e)}")
            self.update_status("Ready")
    
    # VirusTotal scan function
    def virustotal_scan(self):
        target = self.vt_entry.get().strip()
        scan_type = self.vt_type.get().strip()
        
        if not target:
            messagebox.showerror("Error", "Please enter a target to scan")
            return
        
        if not self.api_config["virustotal_api_key"]:
            messagebox.showerror("Error", "VirusTotal API key not configured")
            return
        
        self.update_status(f"Scanning {target} with VirusTotal...")
        self.vt_output.delete(1.0, tk.END)
        
        try:
            self.vt_output.insert(tk.END, f"=== VirusTotal Scan: {target} ({scan_type}) ===\n\n")
            
            params = {"apikey": self.api_config["virustotal_api_key"]}
            
            if scan_type == "URL":
                # URL scan
                params["resource"] = target
                response = requests.get("https://www.virustotal.com/vtapi/v2/url/report", params=params)
                
                if response.status_code == 200:
                    result = response.json()
                    if result["response_code"] == 1:
                        self.vt_output.insert(tk.END, f"Scan Date: {result['scan_date']}\n")
                        self.vt_output.insert(tk.END, f"Positives: {result['positives']}/{result['total']}\n")
                        self.vt_output.insert(tk.END, f"Permalink: {result['permalink']}\n\n")
                        
                        self.vt_output.insert(tk.END, "Scan Results:\n")
                        for scanner, scan in result["scans"].items():
                            self.vt_output.insert(tk.END, f"{scanner}: {scan['result']} ({scan['detected']})\n")
                    else:
                        self.vt_output.insert(tk.END, "No results found. Submitting for analysis...\n")
                        
                        # Submit for analysis
                        params = {"apikey": self.api_config["virustotal_api_key"], "url": target}
                        response = requests.post("https://www.virustotal.com/vtapi/v2/url/scan", data=params)
                        
                        if response.status_code == 200:
                            result = response.json()
                            self.vt_output.insert(tk.END, f"Scan ID: {result['scan_id']}\n")
                            self.vt_output.insert(tk.END, "Please check back later for results\n")
                        else:
                            self.vt_output.insert(tk.END, f"Error submitting for analysis: HTTP {response.status_code}\n")
                else:
                    self.vt_output.insert(tk.END, f"Error: HTTP {response.status_code}\n")
            
            elif scan_type == "Domain":
                # Domain report
                params["domain"] = target
                response = requests.get("https://www.virustotal.com/vtapi/v2/domain/report", params=params)
                
                if response.status_code == 200:
                    result = response.json()
                    if "Webutation domain info" in result:
                        self.vt_output.insert(tk.END, "Webutation Info:\n")
                        web = result["Webutation domain info"]
                        self.vt_output.insert(tk.END, f"Safety Score: {web['Safety score']}/100\n")
                        self.vt_output.insert(tk.END, f"Verdict: {web['Verdict']}\n")
                        self.vt_output.insert(tk.END, f"Adult Content: {web['Adult content']}\n\n")
                    
                    if "whois" in result:
                        self.vt_output.insert(tk.END, "WHOIS Information:\n")
                        self.vt_output.insert(tk.END, f"{result['whois']}\n\n")
                    
                    if "detected_urls" in result and result["detected_urls"]:
                        self.vt_output.insert(tk.END, "Malicious URLs:\n")
                        for item in result["detected_urls"]:
                            self.vt_output.insert(tk.END, f"{item['url']} - {item['positives']}/{item['total']} - {item['scan_date']}\n")
                    else:
                        self.vt_output.insert(tk.END, "No malicious URLs detected\n")
                else:
                    self.vt_output.insert(tk.END, f"Error: HTTP {response.status_code}\n")
            
            elif scan_type == "IP":
                # IP address report
                params["ip"] = target
                response = requests.get("https://www.virustotal.com/vtapi/v2/ip-address/report", params=params)
                
                if response.status_code == 200:
                    result = response.json()
                    if "detected_urls" in result and result["detected_urls"]:
                        self.vt_output.insert(tk.END, "Malicious URLs:\n")
                        for item in result["detected_urls"]:
                            self.vt_output.insert(tk.END, f"{item['url']} - {item['positives']}/{item['total']} - {item['scan_date']}\n")
                    else:
                        self.vt_output.insert(tk.END, "No malicious URLs detected\n")
                    
                    if "resolutions" in result and result["resolutions"]:
                        self.vt_output.insert(tk.END, "\nResolutions:\n")
                        for item in result["resolutions"][:10]:  # Show first 10
                            self.vt_output.insert(tk.END, f"{item['hostname']} - {item['last_resolved']}\n")
                else:
                    self.vt_output.insert(tk.END, f"Error: HTTP {response.status_code}\n")
            
            elif scan_type == "File Hash":
                # File hash report
                params["resource"] = target
                response = requests.get("https://www.virustotal.com/vtapi/v2/file/report", params=params)
                
                if response.status_code == 200:
                    result = response.json()
                    if result["response_code"] == 1:
                        self.vt_output.insert(tk.END, f"Scan Date: {result['scan_date']}\n")
                        self.vt_output.insert(tk.END, f"Positives: {result['positives']}/{result['total']}\n")
                        self.vt_output.insert(tk.END, f"Permalink: {result['permalink']}\n")
                        self.vt_output.insert(tk.END, f"SHA1: {result['sha1']}\n")
                        self.vt_output.insert(tk.END, f"SHA256: {result['sha256']}\n")
                        self.vt_output.insert(tk.END, f"MD5: {result['md5']}\n\n")
                        
                        self.vt_output.insert(tk.END, "Scan Results:\n")
                        for scanner, scan in result["scans"].items():
                            self.vt_output.insert(tk.END, f"{scanner}: {scan['result']} ({scan['detected']})\n")
                    else:
                        self.vt_output.insert(tk.END, "No results found. You may need to upload the file first.\n")
                else:
                    self.vt_output.insert(tk.END, f"Error: HTTP {response.status_code}\n")
            
            self.update_status(f"VirusTotal scan complete: {target}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to perform VirusTotal scan: {str(e)}")
            self.update_status("Ready")
    
    # Enhanced domain analysis with VirusTotal
    def analyze_domain(self):
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showerror("Error", "Please enter a domain")
            return
        
        self.update_status(f"Analyzing domain: {domain}...")
        self.domain_output.delete(1.0, tk.END)
        
        try:
            # Basic domain info
            self.domain_output.insert(tk.END, f"=== Domain Analysis: {domain} ===\n\n")
            
            # WHOIS lookup
            self.domain_output.insert(tk.END, "WHOIS Information:\n")
            try:
                domain_info = whois.whois(domain)
                for key, value in domain_info.items():
                    self.domain_output.insert(tk.END, f"{key}: {value}\n")
            except Exception as e:
                self.domain_output.insert(tk.END, f"WHOIS lookup failed: {str(e)}\n")
            
            self.domain_output.insert(tk.END, "\n")
            
            # DNS records
            self.domain_output.insert(tk.END, "DNS Records:\n")
            record_types = ["A", "AAAA", "MX", "NS", "SOA", "TXT"]
            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(domain, rtype)
                    self.domain_output.insert(tk.END, f"{rtype} Records:\n")
                    for rdata in answers:
                        self.domain_output.insert(tk.END, f"  {rdata}\n")
                except Exception as e:
                    self.domain_output.insert(tk.END, f"  {rtype} lookup failed: {str(e)}\n")
            
            self.domain_output.insert(tk.END, "\n")
            
            # SSL certificate (simplified)
            self.domain_output.insert(tk.END, "SSL Certificate Info:\n")
            try:
                import ssl
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        self.domain_output.insert(tk.END, f"Issuer: {cert['issuer']}\n")
                        self.domain_output.insert(tk.END, f"Valid From: {cert['notBefore']}\n")
                        self.domain_output.insert(tk.END, f"Valid To: {cert['notAfter']}\n")
            except Exception as e:
                self.domain_output.insert(tk.END, f"SSL certificate check failed: {str(e)}\n")
            
            self.domain_output.insert(tk.END, "\n")
            
            # Web server info
            self.domain_output.insert(tk.END, "Web Server Info:\n")
            try:
                response = requests.get(f"http://{domain}", timeout=10)
                self.domain_output.insert(tk.END, f"Status Code: {response.status_code}\n")
                self.domain_output.insert(tk.END, f"Server Header: {response.headers.get('Server', 'Not found')}\n")
            except Exception as e:
                self.domain_output.insert(tk.END, f"Web server check failed: {str(e)}\n")
            
            # VirusTotal domain report if API key is available
            if self.api_config["virustotal_api_key"]:
                self.domain_output.insert(tk.END, "\nVirusTotal Domain Report:\n")
                try:
                    params = {"apikey": self.api_config["virustotal_api_key"], "domain": domain}
                    response = requests.get("https://www.virustotal.com/vtapi/v2/domain/report", params=params)
                    
                    if response.status_code == 200:
                        result = response.json()
                        if "Webutation domain info" in result:
                            web = result["Webutation domain info"]
                            self.domain_output.insert(tk.END, f"Safety Score: {web['Safety score']}/100\n")
                            self.domain_output.insert(tk.END, f"Verdict: {web['Verdict']}\n")
                        
                        if "detected_urls" in result and result["detected_urls"]:
                            self.domain_output.insert(tk.END, "\nMalicious URLs:\n")
                            for item in result["detected_urls"][:5]:  # Show first 5
                                self.domain_output.insert(tk.END, f"{item['url']} - {item['positives']}/{item['total']}\n")
                        else:
                            self.domain_output.insert(tk.END, "No malicious URLs detected\n")
                    else:
                        self.domain_output.insert(tk.END, f"VirusTotal API error: HTTP {response.status_code}\n")
                except Exception as e:
                    self.domain_output.insert(tk.END, f"VirusTotal check failed: {str(e)}\n")
            
            self.update_status(f"Domain analysis complete: {domain}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to analyze domain: {str(e)}")
            self.update_status("Ready")

    # [Previous methods remain unchanged...]
    # Note: In a full implementation, you would also enhance other methods like IP analysis with Shodan,
    # but I've focused on the key additions for HIBP and VirusTotal integration.

# Main application
if __name__ == "__main__":
    root = tk.Tk()
    app = OSINTToolkit(root)
    root.mainloop()
