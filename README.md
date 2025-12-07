# Azure VNET Flow Logs Parser

> **⚠️ Important Note:** Microsoft has announced the retirement of **NSG Flow Logs** by **September 30, 2027**. New NSG Flow Logs cannot be created after **June 30, 2025**. It is strongly recommended to use **Virtual Network (VNET) Flow Logs** for all new deployments and migrate existing NSG Flow Logs. VNET Flow Logs provide enhanced capabilities and are the future standard for traffic analysis in Azure.
>
> For more details, please refer to the [official Azure documentation](https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-overview).

This tool automates the retrieval and analysis of Azure VNET Flow Logs and NSG Flow Logs stored in Azure Blob Storage. It parses the complex JSON log format, handles different log versions, and provides a comprehensive traffic analysis report.

## Features

- **Automated Retrieval**: Connects directly to Azure Blob Storage using a SAS URL.
- **Multi-Format Support**: Handles both Network Security Group (NSG) Flow Logs and VNET Flow Logs.
- **Traffic Analysis**:
  - **Top Talkers**: Identifies top source and destination IPs.
  - **Protocol Usage**: Breakdown of traffic by protocol (TCP/UDP).
  - **Traffic Decisions**: Statistics on Allowed vs. Denied traffic.
  - **Bandwidth Analysis**: Calculates total bandwidth usage (if Version 2 logs are present).
- **Export**: 
  - Saves the fully parsed dataset to `vnet_flow_logs_report.csv` for further analysis.
  - Generates a detailed **Security & Traffic Analysis Report** in Markdown format (`traffic_analysis_report.md`), including:
    - Destination Analysis (Top destinations by session count)
    - Traffic Analysis by Rule Type (Sessions, Data Transferred)
    - HTTPS Traffic Patterns
    - Traffic Volume Analysis (Allowed vs Denied)
    - **Actionable Insights**:
      - **Target Subnets**: Identifies active subnets based on destination traffic.
      - **Security Actions**: Highlights denied traffic and top blocked sources for investigation.
- **Sample Data**: 
  - [`sample_vnet_flow_logs_report.csv`](sample_vnet_flow_logs_report.csv): Demonstrates the parsed CSV format.
  - [`traffic_analysis_report.md`](traffic_analysis_report.md): A sample of the generated Markdown analysis report.

## Prerequisites

- Python 3.8 or higher
- An Azure Storage Account containing Flow Logs
- A SAS URL with Read and List permissions on the storage container

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd Azure--VNET_Flow_Logs-Parser
   ```

2. Create a virtual environment (optional but recommended):
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Open `vnet_flow_log_parser.py`.
2. Locate the `sas_url` variable in the `main()` function.
3. Replace the example URL with your valid Azure Blob Storage SAS URL.
   - Ensure the SAS token has `Read` and `List` permissions.
4. Run the script:
   ```bash
   python vnet_flow_log_parser.py
   ```

## Output

The script generates the following outputs:

1. **Console Summary**: 
   - Displays quick insights into traffic patterns, top talkers, and protocol usage directly in the terminal.

2. **Detailed CSV Report** (`vnet_flow_logs_report.csv`):
   - A comprehensive dataset containing every parsed flow tuple.
   - Includes timestamps, source/destination IPs & ports, protocols, rule names, and throughput metrics (packets/bytes).

3. **Security & Traffic Analysis Report** (`traffic_analysis_report.md`):
   - A formatted Markdown report designed for easy reading and sharing.
   - **Key Sections**:
     - **Destination Analysis**: Top destinations by flow count and data volume.
     - **Rule Analysis**: Traffic patterns grouped by NSG rules and service types (HTTP, SSH, etc.).
     - **HTTPS Insights**: Specific analysis of encrypted traffic on port 443.
     - **Volume Analysis**: Detailed breakdown of data transfer (MB) by direction (Inbound/Outbound) and decision (Allowed/Denied).
     - **Actionable Insights**: 
       - **Target Subnets**: Identifies active subnets receiving traffic.
       - **Security Actions**: Highlights denied traffic sources that require investigation.
