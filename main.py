import os, sys, platform, nmap, threading, subprocess
from flask import Flask, render_template
from flask_socketio import SocketIO, emit

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

def get_nmap_path():
    cmd = "where" if platform.system() == "Windows" else "which"
    try: return subprocess.check_output([cmd, "nmap"]).decode().strip().split('\n')[0]
    except: return "nmap"

NMAP_BIN = get_nmap_path()

@app.route('/')
def index(): return render_template('index.html')

# --- WIFI SCANNER (Fixed Typo & Permissions) ---
@socketio.on('scan_wifi')
def scan_wifi():
    emit('log', {'msg': "📡 Scanning local WiFi spectrum... please wait.", 'type': 'info'})
    try:
        if platform.system() == "Windows":
            # Fixed: mode=bssid (was bash)
            out = subprocess.check_output('netsh wlan show network mode=bssid', shell=True).decode('ascii', errors='ignore')
        else:
            out = subprocess.check_output(['nmcli', '-f', 'SSID,BSSID,SIGNAL,BARS', 'dev', 'wifi']).decode()
        emit('wifi_data', {'raw': out})
        emit('log', {'msg': "✅ WiFi Scan Complete.", 'type': 'success'})
    except Exception as e:
        emit('log', {'msg': "❌ WiFi Card Error: Run as Admin.", 'type': 'danger'})

# --- OFFENSIVE HUB (Vuln & Brute Force) ---
@socketio.on('attack_node')
def attack_node(data):
    target = data.get('ip')
    mode = data.get('type')
    emit('log', {'msg': f"⚡ Engaging {mode} on {target}...", 'type': 'warning'})
    
    def work():
        nm = nmap.PortScanner(nmap_search_path=(NMAP_BIN,))
        if mode == 'vuln':
            nm.scan(hosts=target, arguments="-sV --script=vuln -Pn -T4")
            res = nm[target].get('hostscript', "No vulnerabilities detected.")
        else:
            nm.scan(hosts=target, arguments="-p 22 --script ssh-brute")
            res = nm[target].get('tcp', {}).get(22, {}).get('script', "SSH Port (22) Closed.")
        socketio.emit('attack_results', {'ip': target, 'data': str(res)})
    
    threading.Thread(target=work).start()

# --- DISCOVERY ENGINE (Fixed IndexError) ---
def deep_intel(ip):
    nm = nmap.PortScanner(nmap_search_path=(NMAP_BIN,))
    nm.scan(hosts=ip, arguments="-sV -O -F -Pn --max-rtt-timeout 250ms")
    if ip in nm.all_hosts():
        # SAFETY FIX: Check if osmatch exists before indexing [0]
        os_list = nm[ip].get('osmatch', [])
        os_name = os_list[0]['name'] if os_list else "Protected/Filtered"
        
        payload = {
            'ip': ip,
            'os': os_name,
            'vendor': nm[ip].get('vendor', {}).get(ip, "Generic Hardware"),
            'ports': nm[ip].get('tcp', {})
        }
        socketio.emit('intel_update', payload)

@socketio.on('start_mission')
def start_mission(data):
    target = data.get('target')
    nm = nmap.PortScanner(nmap_search_path=(NMAP_BIN,))
    nm.scan(hosts=target, arguments="-sn -T5")
    for host in nm.all_hosts():
        emit('new_node', {'id': host})
        threading.Thread(target=deep_intel, args=(host,)).start()

if __name__ == '__main__':
    socketio.run(app, host='127.0.0.1', port=5000)