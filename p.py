import pandas as pd
from scapy.all import RawPcapReader, wrpcap, TCP, UDP, IP
import os
from concurrent.futures import ProcessPoolExecutor
import time
import psutil

# Log memory usage (optional)
def log_memory(prefix=""):
    process = psutil.Process(os.getpid())
    mem_mb = process.memory_info().rss / 1024 ** 2
    print(f"{prefix}Memory used: {mem_mb:.2f} MB")

# Preprocess attack CSV into fast lookup dictionary
def preprocess_attacks(df):
    print("Preprocessing attack data...")
    attacks_dict = {}
    for _, row in df.iterrows():
        proto = row['Protocol']
        src_ip = row['Source IP']
        dst_ip = row['Destination IP']
        sport = row['Source Port']
        dport = row['Destination Port']

        key = (proto, src_ip, dst_ip, sport, dport)
        if key not in attacks_dict:
            attacks_dict[key] = []
        attacks_dict[key].append(row)

    print(f"Attack data preprocessed. {len(attacks_dict)} unique attack keys.")
    return attacks_dict

# Match packet against attacks
def match_attack(pkt, attacks_dict):
    if not (IP in pkt and (TCP in pkt or UDP in pkt)):
        return False
    proto = 'tcp' if TCP in pkt else 'udp'
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    sport = pkt[TCP].sport if proto == 'tcp' else pkt[UDP].sport
    dport = pkt[TCP].dport if proto == 'tcp' else pkt[UDP].dport

    attack_key = (proto, src_ip, dst_ip, sport, dport)
    return attack_key in attacks_dict

# Process one pcap file and write output inside subprocess
def process_pcap_and_write(input_path, attacks_dict, output_folder):
    print(f"  Processing: {input_path}")
    benign_packets = []
    count = 0

    try:
        for pkt_data, _ in RawPcapReader(input_path):
            count += 1
            try:
                pkt = IP(pkt_data)
            except:
                continue
            if not match_attack(pkt, attacks_dict):
                benign_packets.append(pkt)

            if count % 1000 == 0:
                print(f"    Processed {count} packets...", end='\r')
    except Exception as e:
        print(f"  Error reading {input_path}: {e}")
        return

    output_path = os.path.join(output_folder, f'benign_{os.path.basename(input_path)}')
    wrpcap(output_path, benign_packets)
    print(f"  Written: {output_path} ({len(benign_packets)} benign packets)")
    log_memory("  After writing: ")

# Wrapper for parallel execution
def process_files_in_parallel(pcap_folder, attacks_dict, output_folder):
    print("\nProcessing files concurrently...")
    with ProcessPoolExecutor(max_workers=2) as executor:  # Adjust workers based on CPU/memory
        for filename in os.listdir(pcap_folder):
            if filename.endswith('.pcap'):
                input_path = os.path.join(pcap_folder, filename)
                executor.submit(process_pcap_and_write, input_path, attacks_dict, output_folder)

# Main
def main():
    start_time = time.time()

    print("Loading ground truth CSV...")
    df = pd.read_csv('NUSW-NB15_GT.csv')
    print(f"Loaded ground truth CSV with {len(df)} rows.")

    attacks_dict = preprocess_attacks(df)

    pcap_folder = r'C:\Users\dheeraj\Downloads\OneDrive_2025-06-21\pcaps 22-1-2015'
    output_folder = 'benign_pcaps'
    os.makedirs(output_folder, exist_ok=True)

    print("\nStarting parallel processing of pcap files...")
    log_memory("Before processing: ")
    process_files_in_parallel(pcap_folder, attacks_dict, output_folder)

    end_time = time.time()
    print(f"\nAll files processed in {end_time - start_time:.2f} seconds.")

if __name__ == "__main__":
    main()
