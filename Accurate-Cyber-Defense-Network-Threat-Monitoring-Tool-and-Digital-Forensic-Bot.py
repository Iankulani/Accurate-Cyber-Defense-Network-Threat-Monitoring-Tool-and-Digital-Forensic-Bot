#!/usr/bin/env python3
"""
Accuarate CyberSecurity Bot - Network Monitoring and Threat Detection Tool
Version: 31.0
Author: Ian Carter Kulanit
Description: A console-based Accuarate cyber security monitoring tool with Telegram integration
"""

import os
import sys
import time
import socket
import threading
import subprocess
import configparser
from datetime import datetime
import json
import select
import struct
import textwrap
import argparse
import requests
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from collections import defaultdict
import logging
from logging.handlers import RotatingFileHandler
import signal
import platform
import ipaddress
import random
import string

# Blue theme color codes
BLUE_THEME = {
    'HEADER': '\033[95m',
    'BLUE': '\033[94m',
    'CYAN': '\033[96m',
    'GREEN': '\033[92m',
    'WARNING': '\033[93m',
    'FAIL': '\033[91m',
    'ENDC': '\033[0m',
    'BOLD': '\033[1m',
    'UNDERLINE': '\033[4m',
    'DARKBLUE': '\033[34m',
    'LIGHTBLUE': '\033[36m'
}

# Global configuration
CONFIG_FILE = 'accuaratecyberbot.ini'
LOG_FILE = 'accuratecyberbot.log'
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB
BACKUP_COUNT = 5

# Global variables
monitoring_active = False
sniffing_active = False
telegram_configured = False
telegram_token = ""
telegram_chat_id = ""
traffic_stats = defaultdict(lambda: defaultdict(int))
packet_count = 0
start_time = datetime.now()
monitored_ips = set()
current_status = "Idle"
traffic_thread = None
sniff_thread = None
exit_event = threading.Event()

# Set up logging
def setup_logging():
    logger = logging.getLogger('cyberbot')
    logger.setLevel(logging.DEBUG)
    
    # Create console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    ch.setFormatter(ch_formatter)
    
    # Create file handler
    fh = RotatingFileHandler(
        LOG_FILE, 
        maxBytes=MAX_LOG_SIZE, 
        backupCount=BACKUP_COUNT
    )
    fh.setLevel(logging.DEBUG)
    fh_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(fh_formatter)
    
    logger.addHandler(ch)
    logger.addHandler(fh)
    
    return logger

logger = setup_logging()

# Configuration management
def load_config():
    global telegram_token, telegram_chat_id, telegram_configured
    
    config = configparser.ConfigParser()
    if os.path.exists(CONFIG_FILE):
        config.read(CONFIG_FILE)
        if 'Telegram' in config:
            telegram_token = config['Telegram'].get('token', '')
            telegram_chat_id = config['Telegram'].get('chat_id', '')
            if telegram_token and telegram_chat_id:
                telegram_configured = True
                logger.info("Telegram configuration loaded successfully")
        if 'MonitoredIPs' in config:
            for ip in config['MonitoredIPs']:
                monitored_ips.add(config['MonitoredIPs'][ip])
            logger.info(f"Loaded {len(monitored_ips)} monitored IPs from config")

def save_config():
    config = configparser.ConfigParser()
    
    if telegram_token and telegram_chat_id:
        config['Telegram'] = {
            'token': telegram_token,
            'chat_id': telegram_chat_id
        }
    
    if monitored_ips:
        config['MonitoredIPs'] = {f'ip{i}': ip for i, ip in enumerate(monitored_ips, 1)}
    
    with open(CONFIG_FILE, 'w') as configfile:
        config.write(configfile)
    
    logger.info("Configuration saved successfully")

# Telegram integration
def send_telegram_message(message):
    if not telegram_configured:
        logger.warning("Telegram not configured. Cannot send message.")
        return False
    
    url = f"https://api.telegram.org/bot{telegram_token}/sendMessage"
    payload = {
        'chat_id': telegram_chat_id,
        'text': message,
        'parse_mode': 'Markdown'
    }
    
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            logger.info("Message sent to Telegram successfully")
            return True
        else:
            logger.error(f"Failed to send Telegram message. Status code: {response.status_code}")
            return False
    except Exception as e:
        logger.error(f"Error sending Telegram message: {str(e)}")
        return False

def test_telegram_connection():
    if not telegram_configured:
        return False, "Telegram not configured"
    
    test_message = "AccurateCyberBot test message\nTime: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    success = send_telegram_message(test_message)
    
    if success:
        return True, "Telegram connection test successful"
    else:
        return False, "Telegram connection test failed"

# Network utilities
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_port(port):
    try:
        port = int(port)
        return 0 < port <= 65535
    except ValueError:
        return False

def ping_ip(ip):
    if not is_valid_ip(ip):
        return False, f"Invalid IP address: {ip}"
    
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '4', ip]
    
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
        return True, output
    except subprocess.CalledProcessError as e:
        return False, str(e.output)

def generate_traffic(target_ip, target_port, duration=10, packet_size=64):
    if not is_valid_ip(target_ip):
        return False, f"Invalid target IP: {target_ip}"
    if not is_valid_port(target_port):
        return False, f"Invalid target port: {target_port}"
    
    target_port = int(target_port)
    duration = int(duration)
    packet_size = int(packet_size)
    
    end_time = time.time() + duration
    packets_sent = 0
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        message = ''.join(random.choices(string.ascii_letters + string.digits, k=packet_size)).encode()
        
        while time.time() < end_time and not exit_event.is_set():
            sock.sendto(message, (target_ip, target_port))
            packets_sent += 1
            time.sleep(0.1)  # Prevent flooding too fast
        
        sock.close()
        return True, f"Sent {packets_sent} packets to {target_ip}:{target_port}"
    except Exception as e:
        return False, f"Error generating traffic: {str(e)}"

# Packet sniffing and monitoring
def packet_callback(packet):
    global packet_count, traffic_stats
    
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if src_ip in monitored_ips or dst_ip in monitored_ips:
            packet_count += 1
            
            # Update traffic statistics
            protocol = packet[IP].proto
            size = len(packet)
            
            if TCP in packet:
                port = packet[TCP].dport
                traffic_stats[dst_ip][port] += size
                traffic_stats[src_ip][port] += size
            elif UDP in packet:
                port = packet[UDP].dport
                traffic_stats[dst_ip][port] += size
                traffic_stats[src_ip][port] += size
            
            # Check for potential threats
            analyze_packet(packet)

def analyze_packet(packet):
    # Basic threat detection
    threats = []
    
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Check for port scanning
        if TCP in packet and packet[TCP].flags == 'S':
            if src_ip in monitored_ips:
                threats.append(f"SYN scan detected from {src_ip}")
        
        # Check for large ICMP packets (potential ping flood)
        if ICMP in packet and len(packet) > 1024:
            threats.append(f"Large ICMP packet detected from {src_ip} to {dst_ip}")
        
        # Check for DNS amplification
        if UDP in packet and packet[UDP].dport == 53 and len(packet) > 512:
            threats.append(f"Potential DNS amplification attack from {src_ip}")
    
    if threats and telegram_configured:
        message = "Potential threats detected:\n" + "\n".join(threats)
        send_telegram_message(message)

def start_monitoring(interface=None):
    global monitoring_active, sniffing_active, sniff_thread, current_status
    
    if monitoring_active:
        return False, "Monitoring is already active"
    
    if not monitored_ips:
        return False, "No IP addresses to monitor. Add IPs first."
    
    try:
        monitoring_active = True
        sniffing_active = True
        current_status = f"Monitoring {len(monitored_ips)} IP(s)"
        
        # Start sniffing in a separate thread
        sniff_thread = threading.Thread(
            target=sniff_packets,
            kwargs={'interface': interface},
            daemon=True
        )
        sniff_thread.start()
        
        logger.info(f"Started monitoring IPs: {', '.join(monitored_ips)}")
        return True, f"Monitoring started for {len(monitored_ips)} IP(s)"
    except Exception as e:
        monitoring_active = False
        sniffing_active = False
        current_status = "Error during monitoring"
        return False, f"Error starting monitoring: {str(e)}"

def sniff_packets(interface=None):
    global sniffing_active
    
    try:
        if interface:
            sniff(prn=packet_callback, store=0, iface=interface, stop_filter=lambda x: not sniffing_active)
        else:
            sniff(prn=packet_callback, store=0, stop_filter=lambda x: not sniffing_active)
    except Exception as e:
        logger.error(f"Error in packet sniffing: {str(e)}")
    finally:
        sniffing_active = False

def stop_monitoring():
    global monitoring_active, sniffing_active, current_status
    
    if not monitoring_active:
        return False, "Monitoring is not active"
    
    monitoring_active = False
    sniffing_active = False
    current_status = "Idle"
    
    if sniff_thread and sniff_thread.is_alive():
        time.sleep(1)  # Give thread time to exit
    
    logger.info("Monitoring stopped")
    return True, "Monitoring stopped successfully"

# Command handlers
def handle_help():
    help_text = f"""
{BLUE_THEME['BLUE']}Accurate cyber Bot Command Help{BLUE_THEME['ENDC']}
{BLUE_THEME['CYAN']}help{BLUE_THEME['ENDC']} - Show this help message
{BLUE_THEME['CYAN']}exit{BLUE_THEME['ENDC']} - Exit the Accurate CyberBot
{BLUE_THEME['CYAN']}ping <IP>{BLUE_THEME['ENDC']} - Ping an IP address
{BLUE_THEME['CYAN']}start monitoring [interface]{BLUE_THEME['ENDC']} - Start monitoring configured IPs
{BLUE_THEME['CYAN']}stop{BLUE_THEME['ENDC']} - Stop monitoring
{BLUE_THEME['CYAN']}view{BLUE_THEME['ENDC']} - View current monitoring statistics
{BLUE_THEME['CYAN']}status{BLUE_THEME['ENDC']} - Show current bot status
{BLUE_THEME['CYAN']}config telegram <token> <chat_id>{BLUE_THEME['ENDC']} - Configure Telegram notifications
{BLUE_THEME['CYAN']}export to telegram{BLUE_THEME['ENDC']} - Export current stats to Telegram
{BLUE_THEME['CYAN']}add ip <IP>{BLUE_THEME['ENDC']} - Add an IP to monitoring list
{BLUE_THEME['CYAN']}remove ip <IP>{BLUE_THEME['ENDC']} - Remove an IP from monitoring list
{BLUE_THEME['CYAN']}list ips{BLUE_THEME['ENDC']} - List all monitored IPs
{BLUE_THEME['CYAN']}generate traffic <IP> <port> [duration] [size]{BLUE_THEME['ENDC']} - Generate network traffic
{BLUE_THEME['CYAN']}test telegram{BLUE_THEME['ENDC']} - Test Telegram connection
"""
    return help_text

def handle_ping(ip):
    success, result = ping_ip(ip)
    if success:
        return f"Ping to {ip} successful:\n{result}"
    else:
        return f"Ping to {ip} failed:\n{result}"

def handle_start_monitoring(interface=None):
    success, message = start_monitoring(interface)
    if success:
        return f"{BLUE_THEME['GREEN']}{message}{BLUE_THEME['ENDC']}"
    else:
        return f"{BLUE_THEME['FAIL']}{message}{BLUE_THEME['ENDC']}"

def handle_stop():
    success, message = stop_monitoring()
    if success:
        return f"{BLUE_THEME['GREEN']}{message}{BLUE_THEME['ENDC']}"
    else:
        return f"{BLUE_THEME['FAIL']}{message}{BLUE_THEME['ENDC']}"

def handle_view():
    if not monitoring_active:
        return "Monitoring is not active. No data to display."
    
    uptime = datetime.now() - start_time
    stats = [
        f"{BLUE_THEME['BLUE']}Monitoring Statistics{BLUE_THEME['ENDC']}",
        f"Uptime: {uptime}",
        f"Packets captured: {packet_count}",
        f"Monitored IPs: {len(monitored_ips)}",
        "",
        f"{BLUE_THEME['CYAN']}Traffic by IP and Port{BLUE_THEME['ENDC']}"
    ]
    
    for ip in monitored_ips:
        if ip in traffic_stats:
            stats.append(f"\nIP: {ip}")
            for port, size in traffic_stats[ip].items():
                stats.append(f"  Port {port}: {size} bytes")
    
    return "\n".join(stats)

def handle_status():
    status_lines = [
        f"{BLUE_THEME['BLUE']}AccurateCyberBot Status{BLUE_THEME['ENDC']}",
        f"Status: {current_status}",
        f"Monitoring active: {'Yes' if monitoring_active else 'No'}",
        f"Telegram configured: {'Yes' if telegram_configured else 'No'}",
        f"Monitored IPs: {len(monitored_ips)}",
        f"Uptime: {datetime.now() - start_time}"
    ]
    return "\n".join(status_lines)

def handle_config_telegram(token, chat_id):
    global telegram_token, telegram_chat_id, telegram_configured
    
    telegram_token = token
    telegram_chat_id = chat_id
    telegram_configured = True
    
    save_config()
    
    # Test the connection
    success, message = test_telegram_connection()
    if success:
        return f"{BLUE_THEME['GREEN']}Telegram configured successfully. {message}{BLUE_THEME['ENDC']}"
    else:
        return f"{BLUE_THEME['FAIL']}Telegram configuration saved but test failed. {message}{BLUE_THEME['ENDC']}"

def handle_export_to_telegram():
    if not telegram_configured:
        return "Telegram not configured. Cannot export."
    
    if not monitoring_active:
        return "Monitoring is not active. No data to export."
    
    uptime = datetime.now() - start_time
    message = [
        f"*accuateBot Monitoring Report*",
        f"*Uptime*: {uptime}",
        f"*Packets captured*: {packet_count}",
        f"*Monitored IPs*: {len(monitored_ips)}",
        "",
        "*Traffic Summary*"
    ]
    
    for ip in monitored_ips:
        if ip in traffic_stats:
            message.append(f"\n*IP*: {ip}")
            for port, size in traffic_stats[ip].items():
                message.append(f"  Port {port}: {size} bytes")
    
    full_message = "\n".join(message)
    success = send_telegram_message(full_message)
    
    if success:
        return "Statistics exported to Telegram successfully"
    else:
        return "Failed to export statistics to Telegram"

def handle_add_ip(ip):
    if not is_valid_ip(ip):
        return f"Invalid IP address: {ip}"
    
    if ip in monitored_ips:
        return f"IP {ip} is already being monitored"
    
    monitored_ips.add(ip)
    save_config()
    return f"Added {ip} to monitoring list"

def handle_remove_ip(ip):
    if ip not in monitored_ips:
        return f"IP {ip} is not in monitoring list"
    
    monitored_ips.remove(ip)
    save_config()
    return f"Removed {ip} from monitoring list"

def handle_list_ips():
    if not monitored_ips:
        return "No IPs are being monitored"
    
    ips = "\n".join(monitored_ips)
    return f"Monitored IPs:\n{ips}"

def handle_generate_traffic(ip, port, duration="10", size="64"):
    success, message = generate_traffic(ip, port, duration, size)
    if success:
        return f"{BLUE_THEME['GREEN']}{message}{BLUE_THEME['ENDC']}"
    else:
        return f"{BLUE_THEME['FAIL']}{message}{BLUE_THEME['ENDC']}"

def handle_test_telegram():
    success, message = test_telegram_connection()
    if success:
        return f"{BLUE_THEME['GREEN']}{message}{BLUE_THEME['ENDC']}"
    else:
        return f"{BLUE_THEME['FAIL']}{message}{BLUE_THEME['ENDC']}"

# Main command processor
def process_command(command):
    parts = command.strip().split()
    if not parts:
        return ""
    
    cmd = parts[0].lower()
    
    try:
        if cmd == "help":
            return handle_help()
        elif cmd == "exit":
            exit_event.set()
            return "Exiting CyberBot..."
        elif cmd == "ping" and len(parts) > 1:
            return handle_ping(parts[1])
        elif cmd == "start" and len(parts) > 1 and parts[1].lower() == "monitoring":
            interface = parts[2] if len(parts) > 2 else None
            return handle_start_monitoring(interface)
        elif cmd == "stop":
            return handle_stop()
        elif cmd == "view":
            return handle_view()
        elif cmd == "status":
            return handle_status()
        elif cmd == "config" and len(parts) > 2 and parts[1].lower() == "telegram":
            if len(parts) < 4:
                return "Usage: config telegram <token> <chat_id>"
            return handle_config_telegram(parts[2], parts[3])
        elif cmd == "export" and len(parts) > 1 and parts[1].lower() == "to" and parts[2].lower() == "telegram":
            return handle_export_to_telegram()
        elif cmd == "add" and len(parts) > 2 and parts[1].lower() == "ip":
            return handle_add_ip(parts[2])
        elif cmd == "remove" and len(parts) > 2 and parts[1].lower() == "ip":
            return handle_remove_ip(parts[2])
        elif cmd == "list" and len(parts) > 1 and parts[1].lower() == "ips":
            return handle_list_ips()
        elif cmd == "generate" and len(parts) > 3 and parts[1].lower() == "traffic":
            ip = parts[2]
            port = parts[3]
            duration = parts[4] if len(parts) > 4 else "10"
            size = parts[5] if len(parts) > 5 else "64"
            return handle_generate_traffic(ip, port, duration, size)
        elif cmd == "test" and len(parts) > 1 and parts[1].lower() == "telegram":
            return handle_test_telegram()
        else:
            return f"Unknown command: {cmd}. Type 'help' for available commands."
    except Exception as e:
        logger.error(f"Error processing command: {str(e)}")
        return f"Error processing command: {str(e)}"

# Signal handler for clean exit
def signal_handler(sig, frame):
    global monitoring_active, sniffing_active
    
    print("\nReceived shutdown signal. Cleaning up...")
    if monitoring_active:
        stop_monitoring()
    
    exit_event.set()
    sys.exit(0)

# Main function
def main():
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Load configuration
    load_config()
    
    print(f"""{BLUE_THEME['BLUE']}
   ____      _          ____        _   
  /     |___ | |__   ___| __ )  ___ | |_ 
 | |   /   \| '_ \ / _ \  _ \ / _ \| __|
 | |__|       |_) |  __/ |_) | (_) | |_ 
  \____\___/|_.__/ \___|____/ \___/ \__|
                                         
{BLUE_THEME['ENDC']}""")
    print(f"{BLUE_THEME['CYAN']}Cyber Defense Bot - Network Monitoring and Threat Detection Tool{BLUE_THEME['ENDC']}")
    print(f"{BLUE_THEME['DARKBLUE']}Type 'help' for available commands{BLUE_THEME['ENDC']}")
    print(f"{BLUE_THEME['DARKBLUE']}Current status: {current_status}{BLUE_THEME['ENDC']}\n")
    
    while not exit_event.is_set():
        try:
            command = input(f"{BLUE_THEME['BLUE']}Accuraetbot> {BLUE_THEME['ENDC']}")
            result = process_command(command)
            if result:
                print(result)
            
            if command.strip().lower() == "exit":
                break
        except KeyboardInterrupt:
            print("\nUse 'exit' command to quit or 'help' for available commands")
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            print(f"{BLUE_THEME['FAIL']}Error: {str(e)}{BLUE_THEME['ENDC']}")

if __name__ == "__main__":
    main()