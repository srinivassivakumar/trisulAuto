#!/usr/bin/env python3
"""
Extract 15 IPs from tcp-report.html that:
1. Are classified as INTERNAL ISSUE
2. Have meters 0, 2, and 4 all present:
   - Meter 0: Latency Internal (µs)
   - Meter 2: Retransmitted Packets Internal
   - Meter 4: Retransmission Rate % Internal
"""

import re

def extract_ips_with_meters():
    """Extract IPs from html report matching the criteria"""
    report_path = r"C:\sri\trisulauto\tcp-report.html"
    
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            html = f.read()
    except OSError:
        print("Error: Could not read tcp-report.html")
        return []
    
    ip_pattern = r'data-ip="([^"]+)"'
    classification_pattern = r'<div class="classification (\w+)">🎯'
    
    # Meter indicators in the issue-metric divs
    meter_0_pattern = r'Latency Internal \(µs\)'
    meter_2_pattern = r'Retransmitted Packets Internal'
    meter_4_pattern = r'Retransmission Rate % Internal'
    
    filtered_ips = []
    seen = set()
    total_ips = 0
    
    # Find each IP and bound it to next IP or EOF
    for ip_match in re.finditer(ip_pattern, html):
        ip = ip_match.group(1)
        total_ips += 1
        start_pos = ip_match.start()
        
        # Find boundary to next IP
        remaining = html[ip_match.end():]
        next_match = re.search(ip_pattern, remaining)
        if next_match:
            end_pos = ip_match.end() + next_match.start()
        else:
            end_pos = len(html)
        
        # Extract section for this IP
        section = html[start_pos:end_pos]
        
        # Check classification is "internal"
        class_match = re.search(classification_pattern, section)
        if not class_match or class_match.group(1) != "internal":
            continue
        
        # Check for all three meters
        has_0 = meter_0_pattern in section
        has_2 = meter_2_pattern in section
        has_4 = meter_4_pattern in section
        
        if has_0 and has_2 and has_4 and ip not in seen:
            seen.add(ip)
            filtered_ips.append(ip)
    
    return filtered_ips

if __name__ == "__main__":
    ips = extract_ips_with_meters()
    print(f"Found {len(ips)} IPs with INTERNAL classification and meters 0, 2, 4:")
    print("=" * 70)
    for i, ip in enumerate(ips, 1):
        print(f"{i:2}. {ip}")
    print("=" * 70)
    print(f"Total: {len(ips)} IPs")
