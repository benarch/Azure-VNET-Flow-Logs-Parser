# Network Traffic Analysis Report

**Generated on:** 2025-12-07 23:34:34

**Total Records Analyzed:** 305

## 1. Destination Analysis

Top destinations by flow count and total volume.

| dest_ip         |   Flow Count |    Total MB |
|:----------------|-------------:|------------:|
| 192.168.10.254  |           76 | 0.0806808   |
| 20.15.141.192   |           60 | 0.00342941  |
| 20.15.141.193   |           36 | 0.0021286   |
| 13.83.125.0     |           24 | 0.00141907  |
| 20.242.181.0    |           19 | 0.00118256  |
| 185.199.108.133 |           14 | 0.000827789 |
| 185.199.109.133 |           14 | 0.000827789 |
| 185.199.110.133 |           14 | 0.000827789 |
| 185.199.111.133 |           12 | 0.000709534 |
| 13.83.125.1     |            8 | 0.000473022 |
| 20.242.181.1    |            8 | 0.000473022 |
| 20.60.251.225   |            4 | 0.213868    |
| 83.98.155.30    |            2 | 0.000133514 |
| 77.161.101.5    |            2 | 0.000133514 |
| 5.200.6.34      |            2 | 0.000133514 |
| 194.104.0.153   |            2 | 0.000133514 |
| 185.51.192.62   |            2 | 0.000133514 |
| 178.239.19.59   |            2 | 0.000133514 |
| 172.233.59.169  |            2 | 0.000133514 |
| 86.80.166.233   |            2 | 0.000133514 |

## 2. Traffic Analysis by Rule Type

Breakdown of traffic patterns grouped by Rule Name.

| rule_name                                                                                                                                                                 | dest_ip         |   dest_port |   protocol | service_type   |   Sessions |   Data Transferred (Bytes) |   Data Transferred (MB) |
|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:----------------|------------:|-----------:|:---------------|-----------:|---------------------------:|------------------------:|
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-hub-nva-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-hub-vm-vm-nsg        | 20.15.141.192   |         443 |          6 | HTTPS          |         60 |                       3596 |             0.00342941  |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-hub-nva-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-hub-vm-vm-nsg        | 20.15.141.193   |         443 |          6 | HTTPS          |         36 |                       2232 |             0.0021286   |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-hub-nva-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-hub-vm-vm-nsg        | 13.83.125.0     |         443 |          6 | HTTPS          |         24 |                       1488 |             0.00141907  |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-hub-nva-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-hub-vm-vm-nsg        | 20.242.181.0    |         443 |          6 | HTTPS          |         19 |                       1240 |             0.00118256  |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-hub-nva-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-hub-vm-vm-nsg        | 185.199.108.133 |         443 |          6 | HTTPS          |         14 |                        868 |             0.000827789 |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-hub-nva-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-hub-vm-vm-nsg        | 185.199.109.133 |         443 |          6 | HTTPS          |         14 |                        868 |             0.000827789 |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-hub-nva-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-hub-vm-vm-nsg        | 185.199.110.133 |         443 |          6 | HTTPS          |         14 |                        868 |             0.000827789 |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-hub-nva-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-hub-vm-vm-nsg        | 185.199.111.133 |         443 |          6 | HTTPS          |         12 |                        744 |             0.000709534 |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-hub-nva-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-hub-vm-vm-nsg        | 13.83.125.1     |         443 |          6 | HTTPS          |          8 |                        496 |             0.000473022 |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-hub-nva-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-hub-vm-vm-nsg        | 20.242.181.1    |         443 |          6 | HTTPS          |          8 |                        496 |             0.000473022 |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-wan-router-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-wan-router-vm-nsg | 192.168.10.254  |          23 |          6 | Other          |          5 |                          0 |             0           |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-wan-router-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-wan-router-vm-nsg | 192.168.10.254  |       38565 |          6 | Other          |          4 |                          0 |             0           |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-hub-nva-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-hub-vm-vm-nsg        | 20.60.251.225   |         443 |          6 | HTTPS          |          4 |                     224257 |             0.213868    |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-wan-router-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-wan-router-vm-nsg | 192.168.10.254  |        2613 |          6 | Other          |          4 |                          0 |             0           |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-hub-nva-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-hub-vm-vm-nsg        | 194.104.0.153   |         123 |         17 | Other          |          2 |                        140 |             0.000133514 |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-hub-nva-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-hub-vm-vm-nsg        | 86.80.166.233   |         123 |         17 | Other          |          2 |                        140 |             0.000133514 |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-hub-nva-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-hub-vm-vm-nsg        | 172.233.59.169  |         123 |         17 | Other          |          2 |                        140 |             0.000133514 |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-hub-nva-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-hub-vm-vm-nsg        | 178.239.19.59   |         123 |         17 | Other          |          2 |                        140 |             0.000133514 |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-hub-nva-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-hub-vm-vm-nsg        | 185.51.192.62   |         123 |         17 | Other          |          2 |                        140 |             0.000133514 |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-hub-nva-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-hub-vm-vm-nsg        | 83.98.155.30    |         123 |         17 | Other          |          2 |                        140 |             0.000133514 |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-hub-nva-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-hub-vm-vm-nsg        | 77.161.101.5    |         123 |         17 | Other          |          2 |                        140 |             0.000133514 |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-hub-nva-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-hub-vm-vm-nsg        | 5.200.6.34      |         123 |         17 | Other          |          2 |                        140 |             0.000133514 |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-wan-router-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-wan-router-vm-nsg | 192.168.10.254  |        5672 |          6 | Other          |          1 |                          0 |             0           |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-wan-router-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-wan-router-vm-nsg | 192.168.10.254  |       57717 |         17 | Other          |          1 |                          0 |             0           |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-wan-router-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-wan-router-vm-nsg | 192.168.10.254  |       60010 |          6 | Other          |          1 |                          0 |             0           |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-wan-router-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-wan-router-vm-nsg | 192.168.10.254  |        6036 |          6 | Other          |          1 |                          0 |             0           |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-wan-router-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-wan-router-vm-nsg | 192.168.10.254  |       62919 |          6 | Other          |          1 |                          0 |             0           |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-wan-router-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-wan-router-vm-nsg | 192.168.10.254  |       56098 |          6 | Other          |          1 |                          0 |             0           |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-wan-router-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-wan-router-vm-nsg | 192.168.10.254  |        8098 |          6 | Other          |          1 |                          0 |             0           |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-wan-router-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-wan-router-vm-nsg | 192.168.10.254  |        7547 |          6 | Other          |          1 |                          0 |             0           |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-wan-router-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-wan-router-vm-nsg | 192.168.10.254  |        8000 |          6 | Other          |          1 |                          0 |             0           |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-wan-router-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-wan-router-vm-nsg | 192.168.10.254  |        8001 |          6 | Other          |          1 |                          0 |             0           |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-wan-router-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-wan-router-vm-nsg | 192.168.10.254  |        8034 |          6 | Other          |          1 |                          0 |             0           |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-wan-router-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-wan-router-vm-nsg | 192.168.10.254  |        8045 |          6 | Other          |          1 |                          0 |             0           |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-wan-router-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-wan-router-vm-nsg | 192.168.10.254  |        8090 |          6 | Other          |          1 |                          0 |             0           |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-wan-router-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-wan-router-vm-nsg | 192.168.10.254  |        7000 |          6 | Other          |          1 |                          0 |             0           |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-wan-router-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-wan-router-vm-nsg | 192.168.10.254  |        8808 |          6 | Other          |          1 |                          0 |             0           |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-wan-router-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-wan-router-vm-nsg | 192.168.10.254  |          81 |          6 | Other          |          1 |                          0 |             0           |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-wan-router-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-wan-router-vm-nsg | 192.168.10.254  |        8154 |          6 | Other          |          1 |                          0 |             0           |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-wan-router-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-wan-router-vm-nsg | 192.168.10.254  |        8291 |          6 | Other          |          1 |                          0 |             0           |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-wan-router-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-wan-router-vm-nsg | 192.168.10.254  |        8443 |          6 | HTTPS-Alt      |          1 |                          0 |             0           |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-wan-router-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-wan-router-vm-nsg | 192.168.10.254  |        8531 |          6 | Other          |          1 |                          0 |             0           |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-wan-router-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-wan-router-vm-nsg | 192.168.10.254  |        8567 |          6 | Other          |          1 |                          0 |             0           |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-wan-router-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-wan-router-vm-nsg | 192.168.10.254  |        8766 |          6 | Other          |          1 |                          0 |             0           |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-wan-router-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-wan-router-vm-nsg | 192.168.10.254  |       53534 |          6 | Other          |          1 |                          0 |             0           |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-wan-router-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-wan-router-vm-nsg | 192.168.10.254  |        8870 |          6 | Other          |          1 |                          0 |             0           |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-wan-router-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-wan-router-vm-nsg | 192.168.10.254  |        8876 |          6 | Other          |          1 |                          0 |             0           |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-wan-router-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-wan-router-vm-nsg | 192.168.10.254  |        8888 |          6 | Other          |          1 |                          0 |             0           |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-wan-router-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-wan-router-vm-nsg | 192.168.10.254  |         902 |          6 | Other          |          1 |                          0 |             0           |
| /subscriptions/87ec57f9-f0ea-43d1-822b-8c9a98d889ca/resourceGroups/customer-wan-router-vm-rg/providers/Microsoft.Network/networkSecurityGroups/customer-wan-router-vm-nsg | 192.168.10.254  |        9096 |          6 | Other          |          1 |                          0 |             0           |

## 3. HTTPS Traffic Patterns (Port 443)

**Total HTTPS Flows:** 213

### Top HTTPS Sources
| src_ip         |   Flow Count |
|:---------------|-------------:|
| 192.168.10.254 |          213 |

### Top HTTPS Destinations
| dest_ip         |   Flow Count |
|:----------------|-------------:|
| 20.15.141.192   |           60 |
| 20.15.141.193   |           36 |
| 13.83.125.0     |           24 |
| 20.242.181.0    |           19 |
| 185.199.109.133 |           14 |
| 185.199.110.133 |           14 |
| 185.199.108.133 |           14 |
| 185.199.111.133 |           12 |
| 13.83.125.1     |            8 |
| 20.242.181.1    |            8 |

## 4. Traffic Volume Analysis

Traffic volume grouped by Traffic Type (Allowed/Denied) and Direction.

| traffic_decision   | traffic_flow   |   Sessions |   Total KB |
|:-------------------|:---------------|-----------:|-----------:|
| B                  | O              |        114 |     0      |
| C                  | I              |          1 |    82.6172 |
| D                  | I              |         75 |     0      |
| E                  | O              |        115 |   232.688  |

## 5. Actionable Insights

Derived actions and observations based on traffic patterns.

### Target Subnets

Identified active subnets based on destination IP traffic (assuming /24).

- **Target Subnet:** 20.15.141.0/24 (customer-a--hub-vnet-rg) - 96 flows
- **Target Subnet:** 192.168.10.0/24 (customer-a--hub-vnet-rg) - 76 flows
- **Target Subnet:** 13.83.125.0/24 (customer-a--hub-vnet-rg) - 32 flows
- **Target Subnet:** 20.242.181.0/24 (customer-a--hub-vnet-rg) - 27 flows
- **Target Subnet:** 185.199.108.0/24 (customer-a--hub-vnet-rg) - 14 flows

### Security Actions

- **Review Denied Traffic:** Detected 75 denied flows. Investigate top sources.
- **Top Denied Sources:** 104.156.155.6, 79.124.58.86, 78.128.114.166

**Top Denied Flows Detail:**
| src_ip         | dest_ip        |   dest_port |   protocol |   Count |
|:---------------|:---------------|------------:|-----------:|--------:|
| 79.124.58.86   | 192.168.10.254 |       38565 |          6 |       4 |
| 78.128.114.166 | 192.168.10.254 |        2613 |          6 |       4 |
| 24.188.46.17   | 192.168.10.254 |          23 |          6 |       2 |
| 104.156.155.6  | 192.168.10.254 |        2352 |          6 |       1 |
| 45.156.131.19  | 192.168.10.254 |        4782 |          6 |       1 |
| 45.156.129.101 | 192.168.10.254 |        5672 |          6 |       1 |
| 44.222.81.115  | 192.168.10.254 |         902 |          6 |       1 |
| 40.124.114.161 | 192.168.10.254 |        4911 |          6 |       1 |
| 35.203.210.139 | 192.168.10.254 |        8870 |          6 |       1 |
| 3.90.12.192    | 192.168.10.254 |        8000 |          6 |       1 |

