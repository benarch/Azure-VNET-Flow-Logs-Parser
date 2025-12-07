# Step-by-Step Instructions

## 1. Generate a SAS URL
To access your flow logs securely, you need a Shared Access Signature (SAS) URL.

1. Go to the **Azure Portal**.
2. Navigate to the **Storage Account** where your Flow Logs are stored.
3. In the left menu, under **Data storage**, select **Containers**.
4. Find the container named `insights-logs-flowlogflowevent` (or similar).
5. Right-click the container and select **Generate SAS**.
6. **Permissions**: Select **Read** and **List**.
7. **Start and expiry**: Set a valid time range.
8. Click **Generate SAS token and URL**.
9. Copy the **Blob SAS URL**.

## 2. Configure the Script
1. Open the file `vnet_flow_log_parser.py` in your code editor.
2. Find the `main()` function at the bottom of the file.
3. Paste your SAS URL into the `sas_url` variable:
   ```python
   sas_url = "https://your-storage-account.blob.core.windows.net/..."
   ```
4. Save the file.

## 3. Run the Analysis
Execute the script from your terminal:

```bash
python vnet_flow_log_parser.py
```

## 4. Analyze Results
- **Terminal**: Review the summary tables for immediate insights on blocked traffic or high bandwidth consumers.
- **CSV Report**: Open `vnet_flow_logs_report.csv` in Excel or PowerBI to create custom charts or filter by specific time ranges and IP addresses.
