import json
import logging
import sys
from datetime import datetime
from urllib.parse import urlparse
import pandas as pd
from azure.storage.blob import ContainerClient

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_container_client_from_sas(sas_url):
    """
    Creates a ContainerClient from a SAS URL.
    """
    try:
        return ContainerClient.from_container_url(sas_url)
    except Exception as e:
        logging.error(f"Failed to create ContainerClient: {e}")
        sys.exit(1)

def parse_flow_tuple(flow_tuple_str, version):
    """
    Parses a single flow tuple string based on the schema version.
    Reference: https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-overview#log-format
    """
    parts = flow_tuple_str.split(',')
    
    # Common fields for Version 1 and 2
    # Format: time, src_ip, dest_ip, src_port, dest_port, protocol, traffic_flow, traffic_decision
    
    ts_val = int(parts[0])
    # Check if timestamp is in milliseconds (likely if > 10 billion)
    if ts_val > 10000000000:
        ts_val = ts_val / 1000.0
        
    base_data = {
        'timestamp': datetime.fromtimestamp(ts_val),
        'src_ip': parts[1],
        'dest_ip': parts[2],
        'src_port': parts[3],
        'dest_port': parts[4],
        'protocol': parts[5],
        'traffic_flow': parts[6], # T=Traffic? No, usually I=Inbound, O=Outbound. Wait, let's check docs.
        # Actually: time, srcIP, destIP, srcPort, destPort, protocol, trafficFlow, trafficDecision, flowState, packets, bytes, packets_src, bytes_src
        'traffic_decision': parts[7]
    }
    
    # Protocol mapping
    proto_map = {'T': 'TCP', 'U': 'UDP'}
    base_data['protocol'] = proto_map.get(base_data['protocol'], base_data['protocol'])

    if version >= 2:
        # Version 2 adds: flowState, packets, bytes, packets_src, bytes_src
        # parts[8]: Flow State (B=Begin, C=Continuance, E=End)
        # parts[9]: Packets sent from src to dest (if available)
        # parts[10]: Bytes sent from src to dest (if available)
        # parts[11]: Packets sent from dest to src (if available)
        # parts[12]: Bytes sent from dest to src (if available)
        
        if len(parts) > 8:
            base_data['flow_state'] = parts[8]
        
        # Helper to safely convert to int
        def safe_int(val):
            return int(val) if val and val.isdigit() else 0

        if len(parts) > 12:
            base_data['packets_src_to_dest'] = safe_int(parts[9])
            base_data['bytes_src_to_dest'] = safe_int(parts[10])
            base_data['packets_dest_to_src'] = safe_int(parts[11])
            base_data['bytes_dest_to_src'] = safe_int(parts[12])
            
            # Total bandwidth calculation
            base_data['total_bytes'] = base_data['bytes_src_to_dest'] + base_data['bytes_dest_to_src']
            base_data['total_packets'] = base_data['packets_src_to_dest'] + base_data['packets_dest_to_src']
        else:
             # Fallback or partial V2
            base_data['total_bytes'] = 0
            base_data['total_packets'] = 0

    return base_data

def process_blobs(container_client):
    """
    Iterates over all blobs in the container, downloads, and parses them.
    """
    all_records = []
    
    logging.info("Listing blobs...")
    blob_list = container_client.list_blobs()
    
    for blob in blob_list:
        logging.info(f"Processing blob: {blob.name}")
        try:
            blob_client = container_client.get_blob_client(blob)
            download_stream = blob_client.download_blob()
            content = download_stream.readall()
            
            if not content:
                continue
                
            data = json.loads(content)
            
            for record in data.get('records', []):
                category = record.get('category')
                if category not in ['NetworkSecurityGroupFlowEvent', 'FlowLogFlowEvent']:
                    continue

                version = 1
                flows_outer_list = []
                base_resource_id = None

                if category == 'NetworkSecurityGroupFlowEvent':
                    properties = record.get('properties', {})
                    version = properties.get('Version', 1)
                    flows_outer_list = properties.get('flows', [])
                    base_resource_id = record.get('resourceId')
                
                elif category == 'FlowLogFlowEvent':
                    version = record.get('flowLogVersion', 1)
                    base_resource_id = record.get('targetResourceID')
                    
                    flow_records = record.get('flowRecords')
                    logging.info(f"Type of flowRecords: {type(flow_records)}")
                    
                    if isinstance(flow_records, dict):
                        logging.info(f"flowRecords keys: {list(flow_records.keys())}")
                        # If it's a dict, maybe it has 'flows' directly?
                        if 'flows' in flow_records:
                            # Treat flow_records as the single flow record object
                            fr = flow_records
                            current_resource_id = fr.get('targetResourceID', base_resource_id)
                            flows_list = fr.get('flows', [])
                            if len(flows_list) > 0:
                                logging.info(f"First item in flows_list keys: {list(flows_list[0].keys())}")
                            
                            for f in flows_list:
                                f['_resource_id'] = current_resource_id
                                flows_outer_list.append(f)
                        else:
                            # Maybe keys are resource IDs? Or something else?
                            # Let's just try to find where 'flows' are.
                            pass
                    elif isinstance(flow_records, list):
                        for fr in flow_records:
                            if isinstance(fr, dict):
                                current_resource_id = fr.get('targetResourceID', base_resource_id)
                                if 'flows' in fr:
                                    for f in fr['flows']:
                                        f['_resource_id'] = current_resource_id
                                        flows_outer_list.append(f)

                for flow_outer in flows_outer_list:
                    # NSG Flow Logs use 'rule', VNET Flow Logs use 'aclID'
                    rule_name = flow_outer.get('rule') or flow_outer.get('aclID', 'N/A')
                    
                    # Determine resource ID (passed from VNET log logic or default)
                    resource_id = flow_outer.get('_resource_id', base_resource_id)

                    # NSG Flow Logs use 'flows', VNET Flow Logs use 'flowGroups'
                    inner_flows = flow_outer.get('flows') or flow_outer.get('flowGroups', [])

                    for flow_inner in inner_flows:
                        mac_address = flow_inner.get('mac')
                        
                        for flow_tuple_str in flow_inner.get('flowTuples', []):
                            parsed_flow = parse_flow_tuple(flow_tuple_str, version)
                            
                            # Add context info
                            parsed_flow['rule_name'] = rule_name
                            parsed_flow['mac_address'] = mac_address
                            parsed_flow['resource_id'] = resource_id
                            
                            all_records.append(parsed_flow)
                            
        except Exception as e:
            logging.error(f"Error processing blob {blob.name}: {e}")
            
    return all_records

def analyze_traffic(df):
    """
    Performs traffic analysis and prints tables.
    """
    if df.empty:
        logging.warning("No records found to analyze.")
        return

    print("\n" + "="*50)
    print("TRAFFIC ANALYSIS REPORT")
    print("="*50 + "\n")

    # 1. General Overview
    print("--- General Overview ---")
    print(f"Total Records: {len(df)}")
    print(f"Date Range: {df['timestamp'].min()} to {df['timestamp'].max()}")
    if 'total_bytes' in df.columns:
        total_traffic_mb = df['total_bytes'].sum() / (1024 * 1024)
        print(f"Total Traffic Volume: {total_traffic_mb:.2f} MB")
    print("\n")

    # 2. Top Talkers (Source IP)
    print("--- Top Source IPs by Flow Count ---")
    top_src = df['src_ip'].value_counts().head(10)
    print(top_src.to_markdown())
    print("\n")

    # 3. Top Destinations
    print("--- Top Destination IPs by Flow Count ---")
    top_dest = df['dest_ip'].value_counts().head(10)
    print(top_dest.to_markdown())
    print("\n")

    # 4. Traffic by Protocol
    print("--- Traffic by Protocol ---")
    proto_counts = df['protocol'].value_counts()
    print(proto_counts.to_markdown())
    print("\n")
    
    # 5. Allowed vs Denied
    print("--- Traffic Decision (Allowed/Denied) ---")
    decision_counts = df['traffic_decision'].value_counts()
    print(decision_counts.to_markdown())
    print("\n")

    # 6. Bandwidth Analysis (if V2 logs present)
    if 'total_bytes' in df.columns and df['total_bytes'].sum() > 0:
        print("--- Top Bandwidth Consumers (Source IP) ---")
        bandwidth_by_src = df.groupby('src_ip')['total_bytes'].sum().sort_values(ascending=False).head(10)
        # Convert to MB
        bandwidth_by_src_mb = bandwidth_by_src / (1024 * 1024)
        print(bandwidth_by_src_mb.to_frame(name='Total MB').to_markdown())
        print("\n")
        
        print("--- Top Bandwidth Consumers (Destination IP) ---")
        bandwidth_by_dest = df.groupby('dest_ip')['total_bytes'].sum().sort_values(ascending=False).head(10)
        bandwidth_by_dest_mb = bandwidth_by_dest / (1024 * 1024)
        print(bandwidth_by_dest_mb.to_frame(name='Total MB').to_markdown())
        print("\n")

    # 7. Detailed Log Table (First 20 records sorted by time)
    print("--- Recent Logs (Detailed) ---")
    # Select key columns for display
    display_cols = ['timestamp', 'src_ip', 'dest_ip', 'dest_port', 'protocol', 'traffic_decision', 'rule_name']
    if 'total_bytes' in df.columns:
        display_cols.append('total_bytes')
    
    # Ensure columns exist
    display_cols = [c for c in display_cols if c in df.columns]
    
    print(df.sort_values(by='timestamp', ascending=False).head(20)[display_cols].to_markdown(index=False))
    print("\n")

def generate_markdown_report(df, output_filename="traffic_analysis_report.md"):
    """
    Generates a detailed markdown report with specific traffic analysis insights.
    """
    if df.empty:
        logging.warning("No data to generate markdown report.")
        return

    with open(output_filename, 'w') as f:
        f.write("# Network Traffic Analysis Report\n\n")
        f.write(f"**Generated on:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"**Total Records Analyzed:** {len(df)}\n\n")

        # --- 1. Destination Analysis ---
        f.write("## 1. Destination Analysis\n\n")
        f.write("Top destinations by flow count and total volume.\n\n")
        
        dest_grp = df.groupby('dest_ip').agg({
            'timestamp': 'count',
            'total_bytes': 'sum' if 'total_bytes' in df.columns else lambda x: 0
        }).rename(columns={'timestamp': 'Flow Count', 'total_bytes': 'Total Bytes'})
        
        dest_grp['Total MB'] = dest_grp['Total Bytes'] / (1024 * 1024)
        dest_grp = dest_grp.sort_values(by='Flow Count', ascending=False).head(20)
        
        f.write(dest_grp[['Flow Count', 'Total MB']].to_markdown())
        f.write("\n\n")

        # --- 2. Traffic Analysis by Rule Type ---
        f.write("## 2. Traffic Analysis by Rule Type\n\n")
        f.write("Breakdown of traffic patterns grouped by Rule Name.\n\n")

        # Service Mapping
        port_service_map = {
            '80': 'HTTP', '443': 'HTTPS', '22': 'SSH', '3389': 'RDP',
            '53': 'DNS', '21': 'FTP', '25': 'SMTP', '110': 'POP3',
            '143': 'IMAP', '3306': 'MySQL', '1433': 'MSSQL', '5432': 'PostgreSQL',
            '8080': 'HTTP-Alt', '8443': 'HTTPS-Alt'
        }
        
        # Ensure dest_port is string for mapping
        df['dest_port_str'] = df['dest_port'].astype(str)
        df['service_type'] = df['dest_port_str'].map(port_service_map).fillna('Other')

        # Grouping
        rule_cols = ['rule_name', 'dest_ip', 'dest_port', 'protocol', 'service_type']
        rule_grp = df.groupby(rule_cols).agg({
            'timestamp': 'count',
            'total_bytes': 'sum' if 'total_bytes' in df.columns else lambda x: 0
        }).rename(columns={'timestamp': 'Sessions', 'total_bytes': 'Data Transferred (Bytes)'})
        
        rule_grp['Data Transferred (MB)'] = rule_grp['Data Transferred (Bytes)'] / (1024 * 1024)
        
        # Sort by Sessions within groups is hard in one go, so just sort by Sessions desc
        rule_grp = rule_grp.sort_values(by='Sessions', ascending=False).head(50).reset_index()
        
        f.write(rule_grp.to_markdown(index=False))
        f.write("\n\n")

        # --- 3. HTTPS Traffic Patterns ---
        f.write("## 3. HTTPS Traffic Patterns (Port 443)\n\n")
        https_df = df[df['dest_port_str'] == '443']
        
        if not https_df.empty:
            f.write(f"**Total HTTPS Flows:** {len(https_df)}\n\n")
            
            f.write("### Top HTTPS Sources\n")
            https_src = https_df['src_ip'].value_counts().head(10).to_frame(name='Flow Count')
            f.write(https_src.to_markdown())
            f.write("\n\n")
            
            f.write("### Top HTTPS Destinations\n")
            https_dest = https_df['dest_ip'].value_counts().head(10).to_frame(name='Flow Count')
            f.write(https_dest.to_markdown())
            f.write("\n\n")
        else:
            f.write("No HTTPS traffic detected.\n\n")

        # --- 4. Traffic Volume Analysis ---
        f.write("## 4. Traffic Volume Analysis\n\n")
        
        if 'total_bytes' in df.columns:
            total_bytes = df['total_bytes'].sum()
            total_mb = total_bytes / (1024 * 1024)
            f.write(f"**Total Data Transferred:** {total_mb:.4f} MB\n\n")
            
            # Direction Breakdown
            if 'traffic_flow' in df.columns:
                direction_grp = df.groupby('traffic_flow')['total_bytes'].sum().reset_index()
                direction_grp['Total MB'] = direction_grp['total_bytes'] / (1024 * 1024)
                direction_grp['Direction'] = direction_grp['traffic_flow'].map({'I': 'Inbound', 'O': 'Outbound'}).fillna(direction_grp['traffic_flow'])
                f.write("### Volume by Direction\n")
                f.write(direction_grp[['Direction', 'Total MB']].to_markdown(index=False))
                f.write("\n\n")

        f.write("### Volume by Decision & Direction\n")
        f.write("Traffic volume grouped by Traffic Type (Allowed/Denied) and Direction.\n\n")
        
        # Group by Decision and Flow Direction
        # traffic_decision: A (Allowed), D (Denied)
        # traffic_flow: I (Inbound), O (Outbound)
        
        vol_grp = df.groupby(['traffic_decision', 'traffic_flow']).agg({
            'timestamp': 'count',
            'total_bytes': 'sum' if 'total_bytes' in df.columns else lambda x: 0
        }).rename(columns={'timestamp': 'Sessions', 'total_bytes': 'Total Bytes'})
        
        vol_grp['Total MB'] = vol_grp['Total Bytes'] / (1024 * 1024)
        
        vol_grp = vol_grp.reset_index()
        f.write(vol_grp[['traffic_decision', 'traffic_flow', 'Sessions', 'Total MB']].to_markdown(index=False))
        f.write("\n\n")

        # --- 5. Actionable Insights ---
        f.write("## 5. Actionable Insights\n\n")
        f.write("Derived actions and observations based on traffic patterns.\n\n")

        # A. Target Subnets
        f.write("### Target Subnets\n\n")
        f.write("Identified active subnets based on destination IP traffic (assuming /24).\n\n")
        
        def get_subnet(ip):
            if pd.isna(ip) or str(ip).count('.') != 3:
                return 'Unknown'
            return '.'.join(str(ip).split('.')[:3]) + '.0/24'

        def get_rg_name(rid):
            if pd.isna(rid): return 'Unknown-RG'
            parts = str(rid).split('/')
            if 'resourceGroups' in parts:
                try:
                    idx = parts.index('resourceGroups')
                    return parts[idx+1]
                except:
                    return 'Unknown-RG'
            return 'Unknown-RG'

        df['dest_subnet'] = df['dest_ip'].apply(get_subnet)
        df['resource_group'] = df['resource_id'].apply(get_rg_name)

        subnet_grp = df.groupby(['dest_subnet', 'resource_group']).size().reset_index(name='Flow Count')
        subnet_grp = subnet_grp.sort_values(by='Flow Count', ascending=False).head(5)

        for _, row in subnet_grp.iterrows():
            f.write(f"- **Target Subnet:** {row['dest_subnet']} ({row['resource_group']}) - {row['Flow Count']} flows\n")
        
        f.write("\n")

        # B. Security Actions (Denied Traffic)
        f.write("### Security Actions\n\n")
        denied_df = df[df['traffic_decision'] == 'D']
        
        if not denied_df.empty:
            f.write(f"- **Review Denied Traffic:** Detected {len(denied_df)} denied flows. Investigate top sources.\n")
            top_denied_src = denied_df['src_ip'].value_counts().head(3).index.tolist()
            f.write(f"- **Top Denied Sources:** {', '.join(top_denied_src)}\n")
            
            f.write("\n**Top Denied Flows Detail:**\n")
            denied_grp = denied_df.groupby(['src_ip', 'dest_ip', 'dest_port', 'protocol']).size().reset_index(name='Count')
            denied_grp = denied_grp.sort_values(by='Count', ascending=False).head(10)
            f.write(denied_grp.to_markdown(index=False))
        else:
            f.write("- **No Denied Traffic:** No blocked flows detected in this period.\n")
        f.write("\n\n")

    logging.info(f"Markdown report generated: {output_filename}")

def main():
    # Example SAS URL provided by user
    sas_url = "https://customeraflowlogs.blob.core.windows.net/insights-logs-flowlogflowevent?sp=rl&st=2025-12-07T20:07:36Z&se=2025-12-08T04:22:36Z&skoid=874455de-f57c-425e-9896-fee7985f4a07&sktid=21ef3553-ac23-4d67-a0b7-fa3d7d0d75e1&skt=2025-12-07T20:07:36Z&ske=2025-12-08T04:22:36Z&sks=b&skv=2024-11-04&spr=https&sv=2024-11-04&sr=c&sig=3tfEe4ZN%2BXcbqPPavH6NMjyKlFE2a%2F3U4i8bcMRDhQg%3D"
    
    logging.info("Starting VNET Flow Log Parser...")
    
    container_client = get_container_client_from_sas(sas_url)
    
    records = process_blobs(container_client)
    
    if not records:
        logging.info("No flow log records found.")
        return

    logging.info(f"Processed {len(records)} records. Creating DataFrame...")
    df = pd.DataFrame(records)
    
    # Ensure timestamp is datetime
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    analyze_traffic(df)
    
    # Generate Markdown Report
    generate_markdown_report(df)
    
    # Optional: Save to CSV
    output_file = "vnet_flow_logs_report.csv"
    df.to_csv(output_file, index=False)
    logging.info(f"Full report saved to {output_file}")

if __name__ == "__main__":
    main()
