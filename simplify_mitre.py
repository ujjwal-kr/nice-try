import json
import os

def simplify_stix(input_path, output_path):
    print(f"Processing {input_path}...")
    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    simplified = []
    
    for obj in data.get('objects', []):
        if obj.get('type') == 'attack-pattern':
            # Extract MITRE ID
            mitre_id = None
            for ref in obj.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    mitre_id = ref.get('external_id')
                    break
            
            if mitre_id:
                simplified.append({
                    "id": mitre_id,
                    "name": obj.get('name', 'Unknown'),
                    "description": obj.get('description', '').replace('\n', ' '),
                    "url": f"https://attack.mitre.org/techniques/{mitre_id}"
                })

    # Sort by ID
    simplified.sort(key=lambda x: x['id'])

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(simplified, f, indent=2)
    
    print(f"Saved {len(simplified)} techniques to {output_path} (JSON Array format)")

if __name__ == "__main__":
    # Ensure data directory exists
    if not os.path.exists('data'):
        print("Error: 'data' directory not found.")
        exit(1)

    # Process Enterprise ATT&CK
    if os.path.exists('data/enterprise-attack.json'):
        simplify_stix('data/enterprise-attack.json', 'data/mitre_simple.json')
    else:
        print("data/enterprise-attack.json not found.")
