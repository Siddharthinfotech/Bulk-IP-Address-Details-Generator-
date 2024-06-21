import csv
import os
from ipwhois import IPWhois
import pandas as pd

# Function to perform WHOIS lookup and return the relevant information
def perform_whois_lookup(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_whois()
        return {
            'ip': ip,
            'asn': res.get('asn', ''),
            'asn_country_code': res.get('asn_country_code', ''),
            'asn_description': res.get('asn_description', ''),
            'asn_date': res.get('asn_date', ''),
            'nets': res.get('nets', [])
        }
    except Exception as e:
        return {
            'ip': ip,
            'error': str(e)
        }

# Specify the input and output file paths
input_file = 'input_ips.csv'  # Change this to the full path if needed
output_file = 'output_whois.csv'

# Check if the input file exists
if not os.path.isfile(input_file):
    print(f"Error: The file {input_file} does not exist.")
else:
    try:
        # Read IP addresses from CSV
        ip_list = []
        with open(input_file, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                if 'ip' in row:
                    ip_list.append(row['ip'])
                else:
                    print("Error: 'ip' column not found in the CSV file.")
                    break

        if not ip_list:
            print("Error: No IP addresses found in the input file.")
        else:
            # Perform WHOIS lookup for each IP address
            whois_results = []
            for ip in ip_list:
                whois_results.append(perform_whois_lookup(ip))

            # Create a DataFrame to store the results
            df = pd.DataFrame(whois_results)

            # Flatten the 'nets' column for better readability
            if 'nets' in df.columns:
                nets_df = df['nets'].apply(pd.Series)
                df = df.drop(columns=['nets']).join(nets_df)

            # Save results to a new CSV file
            df.to_csv(output_file, index=False)

            print(f"WHOIS results saved to {output_file}")
    except Exception as e:
        print(f"An error occurred while processing the file: {e}")
