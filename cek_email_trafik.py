# Mengecek port dengan TCP dan UDP:
# sudo python3 cek_email_trafik.py --server 192.168.1.100 --interface eth0 --protocol tcp --duration 15

# Mengecek port dengan UDP saja:
# sudo python3 cek_email_trafik.py --server 192.168.1.100 --interface wlan0 --protocol udp --duration 15

# note : belum di tes


import subprocess
import re
import datetime
import os
import argparse

# ======= Argparse (CLI) =======
parser = argparse.ArgumentParser(description="Cek apakah trafik ke server diblokir di jaringan (via tcpdump).")
parser.add_argument('--server', '-s', required=True, help='IP address dari target server (email, DNS, dll)')
parser.add_argument('--interface', '-i', required=True, help='Nama network interface (eth0, wlan0, dll)')
parser.add_argument('--duration', '-d', type=int, default=10, help='Durasi capture dalam detik (default: 10)')
parser.add_argument('--custom-ports', '-p', help='Port tambahan yang ingin dicek (contoh: 2087,2525)', default='')
parser.add_argument('--protocol', '-t', choices=['tcp', 'udp', 'both'], default='both', help='Pilih protokol untuk difilter: tcp, udp, atau both (default: both)')

args = parser.parse_args()

server_ip = args.server
interface = args.interface
capture_duration = args.duration
custom_ports = [int(p.strip()) for p in args.custom_ports.split(",") if p.strip().isdigit()]
protocol_filter = args.protocol

# ======= Port Default =======
ports_to_check = {
    "SMTP (25)": 25,
    "SMTP TLS (587)": 587,
    "SMTP SSL (465)": 465,
    "IMAP (143)": 143,
    "IMAP SSL (993)": 993,
    "POP3 (110)": 110,
    "POP3 SSL (995)": 995,
    "DNS (53)": 53,
    "HTTPS (443)": 443,
}

# Tambah custom port ke list
for port in custom_ports:
    ports_to_check[f"Custom Port {port}"] = port

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
output_dir = f"tcpdump_logs_{timestamp}"
os.makedirs(output_dir, exist_ok=True)

# ======= Fungsi Analisis =======
def analyze_tcpdump(output):
    syn_sent = re.findall(r'SFlags \[S\]', output)
    syn_ack = re.findall(r'SFlags \[S\.A\]', output)
    rst = re.findall(r'SFlags \[R\]', output)

    if syn_sent and syn_ack:
        return "TERBUKA (SYN/ACK diterima)"
    elif syn_sent and rst:
        return "DITOLAK (RST diterima)"
    elif syn_sent and not syn_ack:
        return "TIDAK ADA RESPON (Mungkin DIBLOKIR)"
    elif "UDP" in output:
        return "UDP TERDETEKSI (Trafik mungkin berjalan)"
    else:
        return "TIDAK TERDETEKSI / TIDAK ADA PAKET"

# ======= Proses utama =======
results = []

for name, port in ports_to_check.items():
    print(f"\n🔍 Mengecek port {port} - {name}...")

    # Tentukan filter untuk tcpdump
    filter_protocol = ""
    if protocol_filter == "tcp":
        filter_protocol = "tcp"
    elif protocol_filter == "udp":
        filter_protocol = "udp"
    
    pcap_file = f"{output_dir}/capture_{port}.pcap"
    cmd = [
        "sudo", "timeout", str(capture_duration),
        "tcpdump", "-i", interface, f"host {server_ip} and port {port}",
    ]

    if filter_protocol:
        cmd.append(filter_protocol)
    
    cmd += ["-w", pcap_file]

    try:
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print(f"❌ Gagal menjalankan tcpdump: {e}")
        continue

    # Analisis hasil pcap
    print("📖 Menganalisis hasil...")
    try:
        analyze_cmd = ["tcpdump", "-nn", "-r", pcap_file]
        result = subprocess.run(analyze_cmd, capture_output=True, text=True)
        output = result.stdout
        status = analyze_tcpdump(output)
        results.append((name, port, status))
        print(f"✅ Hasil: {status}")
    except Exception as e:
        print(f"❌ Gagal analisis pcap: {e}")
        results.append((name, port, "ERROR"))

# ======= Simpan hasil =======
result_file = os.path.join(output_dir, "hasil_cek_trafik.txt")
with open(result_file, "w") as f:
    for name, port, status in results:
        f.write(f"{name} (Port {port}): {status}\n")

print(f"\n📝 Hasil disimpan di: {result_file}")
print(f"🔗 File pcap untuk analisis Wireshark: {output_dir}")
