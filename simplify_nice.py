import json
import os

def simplify_nice(input_path, output_path):
    print(f"Processing {input_path}...")
    
    if not os.path.exists(input_path):
        print(f"Error: Input file '{input_path}' not found.")
        return

    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    simplified = []
    
    # valid types we care about
    valid_types = {
        'work_role': 'Role',
        'task': 'Task',
        'knowledge': 'Knowledge',
        'skill': 'Skill',
        'ability': 'Ability'
    }

    for element in data.get('elements', []):
        e_type = element.get('element_type')
        
        if e_type in valid_types:
            # Construct a useful description
            # Some elements have a title, some have text, some have both.
            title = element.get('title', '').strip()
            text = element.get('text', '').strip()
            
            description = text
            if title and title != text:
                if description:
                    description = f"{title}: {description}"
                else:
                    description = title
            
            simplified.append({
                "id": element.get('element_identifier'),
                "type": valid_types[e_type],
                "description": description
            })

    # Sort by ID
    simplified.sort(key=lambda x: x['id'])

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(simplified, f, indent=2)
    
    print(f"Saved {len(simplified)} NICE elements to {output_path}")

if __name__ == "__main__":
    # Ensure data directory exists
    if not os.path.exists('data'):
        print("Error: 'data' directory not found.")
        exit(1)

    simplify_nice('data/v2_nf_components.json', 'data/nice_simple.json')
