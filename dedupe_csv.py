import pandas as pd
import re
import argparse

def process_resource_id(resource_id):
    """Extracts the deduplication string from Resource ID."""
    if "sha256" in resource_id:
        return resource_id.split("sha256")[0]
    return resource_id

def dedupe_csv(input_csv, output_csv):
    # Read CSV file
    df = pd.read_csv(input_csv)
    
    # Filter rows where Title starts with 'CVE'
    df_cve = df[df['Title'].str.startswith('CVE', na=False)].copy()
    
    # Process Resource ID for deduplication
    df_cve['DedupeKey'] = df_cve['Resource ID'].apply(process_resource_id)
    
    # Dictionary to track unique entries
    dedupe_dict = {}
    
    # List to store processed rows
    new_rows = []
    
    for _, row in df_cve.iterrows():
        key = row['DedupeKey']
        if key in dedupe_dict:
            # Append GIS ID to the first occurrence
            dedupe_dict[key]['GIS ID'] += f", {row['GIS ID']}"
        else:
            # Store the first occurrence
            dedupe_dict[key] = row.to_dict()
            new_rows.append(dedupe_dict[key])
    
    # Convert back to DataFrame
    df_deduped = pd.DataFrame(new_rows)
    
    # Replace original CVE rows with deduplicated ones
    df_non_cve = df[~df['Title'].str.startswith('CVE', na=False)]
    df_final = pd.concat([df_non_cve, df_deduped], ignore_index=True)
    
    # Save the output
    df_final.to_csv(output_csv, index=False)
    print(f"Deduplicated CSV saved as: {output_csv}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Deduplicate CSV based on CVE Titles and Resource ID.')
    parser.add_argument('input_csv', help='Input CSV file path')
    parser.add_argument('output_csv', help='Output CSV file path')
    args = parser.parse_args()
    
    dedupe_csv(args.input_csv, args.output_csv)
