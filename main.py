import os
import json
import google.generativeai as genai

from dotenv import load_dotenv
from typing import Dict, Optional

# ==========================================
# CONFIGURATION
# =========================================
load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")
if not API_KEY:
    print("[!] Warning: GEMINI_API_KEY is missing. Set it via environment or .env file.")
    raise SystemExit("GEMINI_API_KEY is required to run this agent.")

genai.configure(api_key=API_KEY)

# CONSTANTS
MAX_LOOPS = 5
INNER_LOOP_MAX = 3
MODEL_NAME = 'gemini-2.5-flash-preview-09-2025'

# ==========================================
# 1. THE HUNTER (RESEARCH AGENT)
# ==========================================
class HunterAgent:
    def __init__(self):
        self.model = genai.GenerativeModel(
            model_name=MODEL_NAME,
            generation_config=genai.types.GenerationConfig(temperature=0.4)
        )
        
        self.system_prompt = """
        You are a specialized Cybersecurity Research Agent (The Hunter). 
        Your goal: Map raw, informal, or "hood" descriptions of hacker activities to strict professional frameworks.
        
        Task:
        1. Analyze the user's input.
        2. Use Google Search to find the EXACT **MITRE ATT&CK** Technique IDs (Txxxx).
        3. Use Google Search to find the EXACT **NICE Framework** Work Roles and Task IDs.
        4. Refine the text into a professional log entry.
        
        Constraint: You must output valid JSON only.
        """
        
        self.output_format = """
        {
            "refined_text": "Professional summary",
            "mitre_attack": [
                {"id": "TXXXX", "name": "Technique Name"}
            ],
            "knowledge": [
                {"id": "K0001", "description": "Knowledge description"}
            ],
            "skills": [
                {"id": "S0010", "description": "Skill description"}
            ],
            "abilities": [
                {"id": "A0004", "description": "Ability description"}
            ],
            "tasks": [
                {"id": "T0021", "description": "Task description"}
            ],
            "justification": "Why these codes and KSAs match"
        }
        """

        self.focus_instructions = {
            "mitre": "Prioritize MITRE ATT&CK descriptions and ensure the right Txxxx codes are highlighted. KSA entries may be supplemental but only when they arise from the technique analysis.",
            "ksa": "Prioritize Knowledge/Skill/Ability/Task mappings that align with the input. Mention MITRE techniques only if they directly support the required KSAs.",
            "both": "Balance MITRE ATT&CK techniques with Knowledge/Skill/Ability/Task mappings, explaining why each framework element is relevant."
        }

        self.focus_guidance = {
            "mitre": "Only return MITRE references in 'mitre_attack' and keep KSA sections limited to what directly supports the technique. Avoid full KSA lists if not essential.",
            "ksa": "Only return KSA entries in 'knowledge', 'skills', 'abilities', and 'tasks'. Leave 'mitre_attack' empty or explain why no MITRE mapping applies.",
            "both": "Return both MITRE techniques and KSA entries. Each category should justify its outputs against the user’s input."
        }

    def generate_draft(self, user_input: str, feedback: str = "", attempt: int = 1, focus: str = "both") -> Dict:
        print(f"    [Hunter] Executing research pass #{attempt}...")
        
        # Using .replace() instead of f-strings to avoid SyntaxErrors with braces
        prompt = """
        [SYSTEM]
        __SYSTEM_PROMPT__

        [FOCUS]
        __FOCUS_INSTRUCTION__

        [FOCUS GUIDANCE]
        __FOCUS_GUIDANCE__

        [USER INPUT]
        "__USER_INPUT__"
        
        [PREVIOUS FEEDBACK]
        __FEEDBACK__
        
        [REQUIRED JSON OUTPUT FORMAT]
        __OUTPUT_FORMAT__

        [CRITICAL INSTRUCTION]
        If the [PREVIOUS FEEDBACK] contains "[AUDITOR SUGGESTIONS]", you MUST incorporate those specific IDs into your new draft. They are from the internal database and are correct.
        
        [WARNING: LEGACY IDS]
        Do NOT use legacy NICE Framework IDs like K0001, K0002, S0001, etc. unless they are explicitly defined in the context.
        The internal database uses a newer version of the framework.
        If you are unsure, describe the concept and let the Auditor suggest the correct ID.
        """
        
        safe_input = user_input.replace('"', "'")
        safe_feedback = feedback if feedback else "None - First Attempt"
        
        focus_instruction = self.focus_instructions.get(focus, self.focus_instructions["both"])
        focus_guidance = self.focus_guidance.get(focus, self.focus_guidance["both"])
        final_prompt = prompt.replace("__SYSTEM_PROMPT__", self.system_prompt) \
                 .replace("__FOCUS_INSTRUCTION__", focus_instruction) \
                 .replace("__FOCUS_GUIDANCE__", focus_guidance) \
                 .replace("__USER_INPUT__", safe_input) \
                 .replace("__FEEDBACK__", safe_feedback) \
                 .replace("__OUTPUT_FORMAT__", self.output_format)
        
        try:
            chat = self.model.start_chat(history=[]) 
            response = chat.send_message(final_prompt)
            return self._clean_json(response.text)
        except Exception as e:
            print(f"    [!] Hunter Malfunction: {e}")
            return {}

    def _clean_json(self, text: str) -> Dict:
        try:
            # Remove markdown code blocks if present
            clean = text.replace("```json", "").replace("```", "").strip()
            return json.loads(clean)
        except json.JSONDecodeError:
            print(f"    [!] Error: Hunter produced invalid JSON.\nRaw: {text[:100]}...")
            return {}

# ==========================================
# 2. THE AUDITOR (VERIFIER AGENT)
# ==========================================
class AuditorAgent:
    def __init__(self):
        self.model = genai.GenerativeModel(
            model_name=MODEL_NAME,
            generation_config=genai.types.GenerationConfig(temperature=0.0)
        )
        self.mitre_data = []
        self.nice_data = []
        self._load_knowledge_base()
        
        self.system_prompt = """
        You are a Senior Cybersecurity Compliance Auditor.
        Your job is to VERIFY the research of a junior analyst against an INTERNAL DATABASE.
        
        CRITICAL RULES:
        1. **SOURCE OF TRUTH**: The "INTERNAL KNOWLEDGE BASE CONTEXT" provided to you is the ONLY valid source of truth.
        2. **NO OUTSIDE KNOWLEDGE**: Do NOT use your own training data to verify codes. If a code is not in the context, it is INVALID.
        3. **STRICT VERIFICATION**:
           - If the junior analyst uses an ID (e.g., T1566, K0001) that is NOT defined in the "DEFINITIONS OF DRAFT IDS" section, you MUST FAIL the audit.
           - Mark it as "Hallucinated ID" or "Invalid ID".
        4. **ALTERNATIVES**: Use the "POTENTIAL ALTERNATIVES" section to suggest corrections if the draft is wrong.
        
        Process:
        1. Check every ID in the draft against the "DEFINITIONS OF DRAFT IDS".
        2. If an ID is missing from definitions -> FAIL (Reason: Invalid/Hallucinated ID).
        3. If an ID exists but the description in the draft contradicts the definition -> FAIL (Reason: Mismatched Description).
        4. If the ID and description match the context -> PASS.
        """
        
        self.output_format = """
        {
            "status": "PASS" or "FAIL",
            "feedback": "Empty string if PASS, specific instructions on what to fix if FAIL. Suggest specific IDs from the context if applicable."
        }
        """

        self.focus_instructions = {
            "mitre": "Only verify MITRE entries; if NICE entries are present, flag them as extraneous unless justified by an explicit MITRE description.",
            "ksa": "Only verify KSA (NICE) entries. Do NOT fail the audit if MITRE ATT&CK entries are missing or empty. Focus strictly on the accuracy of Knowledge, Skills, Abilities, and Tasks.",
            "both": "Verify both MITRE and NICE entries for accuracy."
        }

    def _load_knowledge_base(self):
        """Loads the simplified MITRE and NICE data into memory."""
        # Load MITRE
        mitre_path = 'data/mitre_simple.json'
        if os.path.exists(mitre_path):
            try:
                with open(mitre_path, 'r', encoding='utf-8') as f:
                    self.mitre_data = json.load(f)
                print(f"    [Auditor] Loaded {len(self.mitre_data)} MITRE techniques.")
            except Exception as e:
                print(f"    [!] Error loading MITRE KB: {e}")
        else:
            print("    [!] MITRE KB not found. Run simplify_mitre.py first.")

        # Load NICE
        nice_path = 'data/nice_simple.json'
        if os.path.exists(nice_path):
            try:
                with open(nice_path, 'r', encoding='utf-8') as f:
                    self.nice_data = json.load(f)
                print(f"    [Auditor] Loaded {len(self.nice_data)} NICE elements.")
            except Exception as e:
                print(f"    [!] Error loading NICE KB: {e}")
        else:
            print("    [!] NICE KB not found. Run simplify_nice.py first.")

    def _search_knowledge_base(self, query_terms: list) -> list:
        """Simple keyword search against both KBs."""
        results = []
        if not self.mitre_data and not self.nice_data:
            return results
            
        # Filter out common stop words
        stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by'}
        terms = [t.lower() for t in query_terms if t.lower() not in stop_words and len(t) > 3]
        
        if not terms:
            return results

        print(f"    [Auditor] Searching KB for keywords: {terms}")
        
        # Helper to search a dataset
        def search_dataset(dataset, source_name):
            local_results = []
            for item in dataset:
                content = (item.get('name', '') + ' ' + item.get('description', '') + ' ' + item.get('type', '')).lower()
                score = sum(1 for term in terms if term in content)
                if score > 0:
                    # Add source tag for clarity
                    item_copy = item.copy()
                    item_copy['_source'] = source_name
                    local_results.append((score, item_copy))
            return local_results

        # Search both
        mitre_results = search_dataset(self.mitre_data, "MITRE ATT&CK")
        nice_results = search_dataset(self.nice_data, "NICE Framework")
        
        # Sort each list by score
        mitre_results.sort(key=lambda x: x[0], reverse=True)
        nice_results.sort(key=lambda x: x[0], reverse=True)
        
        # Take top 20 from each to ensure balance and better recall
        final_results = []
        final_results.extend([r[1] for r in mitre_results[:20]])
        final_results.extend([r[1] for r in nice_results[:20]])
        
        return final_results

    def _generate_search_terms(self, user_input: str, draft_json: Dict) -> list:
        """
        Uses the LLM to generate smart search terms based on the user input and the draft.
        This allows the Auditor to 'guess' relevant concepts that might not be explicitly named.
        """
        draft_summary = json.dumps(draft_json, indent=2)[:1000] # Truncate to save tokens if huge
        
        prompt = f"""
        [TASK]
        Analyze the USER INPUT and the DRAFT ANALYSIS.
        Generate a list of 5-8 specific search keywords or phrases to query an internal MITRE/NICE database.
        
        [GOAL]
        Find relevant MITRE Techniques and NICE Knowledge/Skills/Abilities/Tasks that might be missing or misidentified.
        Think about synonyms, related concepts, and specific technical terms.
        
        [USER INPUT]
        "{user_input}"
        
        [DRAFT ANALYSIS SAMPLE]
        {draft_summary}
        
        [OUTPUT FORMAT]
        Return ONLY a comma-separated list of 5-8 SINGLE KEYWORDS or SHORT CONCEPTS. 
        Do NOT use long sentences.
        Example: Phishing, SIEM, Logs, Malware, Headers, SMTP, Triage
        """
        
        try:
            response = self.model.generate_content(prompt)
            # Split by comma first
            raw_terms = [t.strip() for t in response.text.split(',')]
            
            # Flatten: Split phrases into individual words to ensure broad matching
            final_terms = []
            for term in raw_terms:
                # Split by space
                words = term.split()
                final_terms.extend(words)
            
            # Remove duplicates and short words
            final_terms = list(set([w for w in final_terms if len(w) > 3]))
            
            print(f"    [Auditor] Generated smart search terms: {final_terms}")
            return final_terms
        except Exception as e:
            print(f"    [!] Failed to generate search terms: {e}")
            # Fallback to naive splitting
            return user_input.replace(',', ' ').replace('.', ' ').split()

    def verify(self, original_input: str, draft_json: Dict, focus: str = "both") -> Dict:
        print(f"    [Auditor] Verifying data against official sources...")
        
        # Step 1: Extract IDs from draft to look them up specifically
        ids = []
        # Check MITRE IDs
        if 'mitre_attack' in draft_json:
            for item in draft_json['mitre_attack']:
                if 'id' in item:
                    ids.append(item['id'])
        
        # Check NICE IDs
        nice_keys = ['knowledge', 'skills', 'abilities', 'tasks']
        for key in nice_keys:
            if key in draft_json:
                for item in draft_json[key]:
                    if 'id' in item:
                        ids.append(item['id'])

        ids = sorted(list(set(ids)))

        # Step 2: Build Context
        internal_context = ""
        
        # A. Look up the specific IDs the Hunter chose
        found_items = []
        
        # Search MITRE
        if self.mitre_data:
            found_items.extend([item for item in self.mitre_data if item['id'] in ids])
            
        # Search NICE
        if self.nice_data:
            found_items.extend([item for item in self.nice_data if item['id'] in ids])
            
        if found_items:
            internal_context += "=== DEFINITIONS OF DRAFT IDS ===\n"
            for item in found_items:
                internal_context += json.dumps(item, indent=2) + "\n"
        
        # B. Perform INTELLIGENT Keyword Search
        # Use LLM to generate search terms instead of naive splitting
        search_terms = self._generate_search_terms(original_input, draft_json)
        alternatives = self._search_knowledge_base(search_terms)
        
        if alternatives:
            internal_context += "\n=== POTENTIAL ALTERNATIVES FOUND IN KB ===\n"
            internal_context += "(The junior analyst may have missed these. Use them to correct the draft if necessary.)\n"
            for item in alternatives:
                internal_context += json.dumps(item, indent=2) + "\n"

        # C. Perform Targeted Search for Invalid IDs
        # If an ID was used but not found in the KB, search for its DESCRIPTION to find the real ID.
        invalid_id_suggestions = []
        
        # Identify which IDs were in the draft but NOT found in the KB
        found_ids = {item['id'] for item in found_items}
        invalid_ids = [uid for uid in ids if uid not in found_ids]
        
        if invalid_ids:
            print(f"    [Auditor] Investigating {len(invalid_ids)} invalid IDs...")
            
            # Helper to find description in draft
            def get_draft_description(target_id):
                for key in ['mitre_attack', 'knowledge', 'skills', 'abilities', 'tasks']:
                    if key in draft_json:
                        for item in draft_json[key]:
                            if item.get('id') == target_id:
                                return item.get('description', item.get('name', ''))
                return ""

            for uid in invalid_ids:
                desc = get_draft_description(uid)
                if desc:
                    # Determine likely source based on ID format
                    target_source = "NICE Framework" # Default
                    
                    if uid.startswith(('K', 'S', 'A')):
                        target_source = "NICE Framework"
                    elif uid.startswith('T'):
                        # Ambiguous: Could be MITRE Technique (Txxxx) or NICE Task (Txxxx)
                        # Check for dot (MITRE sub-technique)
                        if '.' in uid:
                            target_source = "MITRE ATT&CK"
                        else:
                            # Check context
                            in_mitre = False
                            if 'mitre_attack' in draft_json:
                                for item in draft_json['mitre_attack']:
                                    if item.get('id') == uid:
                                        in_mitre = True
                                        break
                            
                            if in_mitre:
                                target_source = "MITRE ATT&CK"
                            else:
                                target_source = "NICE Framework" # Assume Task if not in MITRE list
                    else:
                        # Fallback to section check
                        if 'mitre_attack' in draft_json:
                            for item in draft_json['mitre_attack']:
                                if item.get('id') == uid:
                                    target_source = "MITRE ATT&CK"
                                    break
                    
                    # Clean description for search
                    clean_desc = desc.replace('Knowledge of', '').replace('Skill in', '').replace('Ability to', '').split()
                    clean_desc = [w for w in clean_desc if len(w) > 3]
                    
                    # Search KB
                    matches = self._search_knowledge_base(clean_desc)
                    
                    # FILTER matches by source
                    filtered_matches = [m for m in matches if m.get('_source') == target_source]
                    
                    # Special handling for T-codes (Task vs Technique)
                    # If we want NICE, ensure we don't get MITRE T-codes
                    if target_source == "NICE Framework":
                         filtered_matches = [m for m in filtered_matches if m.get('_source') == "NICE Framework"]
                    
                    if filtered_matches:
                        best_match = filtered_matches[0] # Top result from correct source
                        # print(f"    [DEBUG] UID: {uid}, Source: {target_source}, Best Match: {best_match['id']} ({best_match.get('_source')})")
                        invalid_id_suggestions.append(f"For invalid {uid} ('{desc[:30]}...'), consider {best_match['id']} ({best_match.get('description', '')[:50]}...)")

        # Step 3: Call the model for verification, now with ripgrep context
        json_str = json.dumps(draft_json, indent=2)
        safe_input = original_input.replace('"', "'")
        
        # Using .replace() to be safe
        verification_template = """
        [SYSTEM]
        __SYSTEM_PROMPT__

        [FOCUS]
        __FOCUS_INSTRUCTION__

        [ORIGINAL USER ACTION]
        "__USER_INPUT__"

        [JUNIOR ANALYST DRAFT]
        __DRAFT_JSON__

        [INTERNAL KNOWLEDGE BASE CONTEXT]
        __INTERNAL_CONTEXT__

        INSTRUCTION: Verify the junior analyst's draft against the internal knowledge base context. The internal knowledge base context is the source of truth.

        [REQUIRED JSON OUTPUT FORMAT]
        __OUTPUT_FORMAT__
        """
        
        focus_instruction = self.focus_instructions.get(focus, self.focus_instructions["both"])
        final_prompt = verification_template.replace("__SYSTEM_PROMPT__", self.system_prompt) \
                            .replace("__FOCUS_INSTRUCTION__", focus_instruction) \
                            .replace("__USER_INPUT__", safe_input) \
                            .replace("__DRAFT_JSON__", json_str) \
                            .replace("__INTERNAL_CONTEXT__", internal_context if internal_context else "No internal context found.") \
                            .replace("__OUTPUT_FORMAT__", self.output_format)
        
        try:
            chat = self.model.start_chat(history=[])
            response = chat.send_message(final_prompt)
            result = json.loads(response.text.replace("```json", "").replace("```", "").strip())
            
            # --- ENHANCEMENT: AUTO-SUGGEST CORRECTIONS ---
            # If the model failed the audit, let's append specific suggestions
            if result.get("status") == "FAIL":
                suggestions = []
                
                # 1. Add specific corrections for invalid IDs (High Priority)
                if invalid_id_suggestions:
                    suggestions.extend(invalid_id_suggestions)
                
                # 2. Add general smart search alternatives (Low Priority)
                if alternatives:
                     # Suggest top 4 IDs (2 MITRE, 2 NICE roughly)
                    for alt in alternatives[:4]:
                        suggestions.append(f"General Suggestion: {alt['id']} ({alt.get('name', alt.get('description', ''))[:50]}...)")
                
                if suggestions:
                    suggestion_text = "\n[AUDITOR SUGGESTIONS]:\n" + "\n".join(suggestions)
                    result["feedback"] += suggestion_text
                    print(f"    [Auditor] Appended {len(suggestions)} suggestions to feedback.")
            
            return result
        except Exception as e:
            print(f"    [!] Auditor Malfunction: {e}")
            return {"status": "FAIL", "feedback": "Auditor crashed. Please retry."}

    def _clean_json(self, text: str) -> Dict:
        try:
            clean = text.replace("```json", "").replace("```", "").strip()
            return json.loads(clean)
        except json.JSONDecodeError:
            return {}

# ==========================================
# 3. THE ORCHESTRATOR (DEEP RESEARCH LOOP)
# ==========================================
class DeepResearchSystem:
    def __init__(self):
        self.hunter = HunterAgent()
        self.auditor = AuditorAgent()

    def run(self, user_input: str):
        print(f"\n[>] Initializing Deep Research Protocol for: '{user_input}'")
        print(f"[>] Max Retries: {MAX_LOOPS}")
        focus = self._prompt_focus()
        
        feedback = ""
        final_output = None
        
        for i in range(1, MAX_LOOPS + 1):
            print(f"\n--- LOOP {i}/{MAX_LOOPS} ---")
            
            # Step 1: Hunter generates draft
            draft = self.hunter.generate_draft(user_input, feedback, attempt=i, focus=focus)
            draft = self._apply_focus_constraints(draft, focus)
            
            if not draft:
                feedback = "Previous JSON was invalid. Output strict JSON."
                print("    [!] Hunter returned empty/invalid JSON. Retrying...")
                continue

            # Step 2: Auditor verifies draft
            audit = self.auditor.verify(user_input, draft, focus=focus)
            
            # Step 3: Decision
            status = audit.get("status", "FAIL").upper()
            feedback = audit.get("feedback", "")
            
            print(f"    [Result] Status: {status}")
            if status == "PASS":
                print("    [>] Verification Successful. Exiting Loop.")
                final_output = draft
                break
            else:
                print(f"    [>] Feedback: {feedback}")
                print("    [>] Retrying with feedback...")
        
        if not final_output:
            print("\n[!] Max loops reached. Returning last best effort.")
            final_output = draft

        self._print_report(user_input, final_output)

    def _prompt_focus(self) -> str:
        question = (
            "What should the agent focus on? (mitre/ksa/both)\n"
            "[Default=both]: "
        )
        while True:
            response = input(question).strip().lower()
            if not response:
                return "both"
            if response in {"mitre", "ksa", "both"}:
                return response
            print("Please answer 'mitre', 'nice', or 'both'.")

    def _read_user_file(self) -> Optional[str]:
        path = input("Enter file path to load: ").strip()
        if not path:
            print("[!] No file path provided. Skipping file import.")
            return None

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
                if not content:
                    print(f"[!] File '{path}' is empty.")
                    return None
                return content
        except Exception as exc:
            print(f"[!] Failed to read '{path}': {exc}")
            return None

    def _print_report(self, original, data):
        if not data: return
        print("\n" + "="*60)
        print(" ✅ FINAL INTELLIGENCE REPORT")
        print("-" * 60)
        print(">> MITRE ATT&CK")
        for m in data.get('mitre_attack', []):
            print(f"   [{m.get('id')}] {m.get('name')}")

        print("-" * 60)
        print(">> KNOWLEDGE (K)")
        for k in data.get('knowledge', []):
            print(f"   [{k.get('id')}] {k.get('description')}")

        print("-" * 60)
        print(">> SKILLS (S)")
        for s in data.get('skills', []):
            print(f"   [{s.get('id')}] {s.get('description')}")

        print("-" * 60)
        print(">> ABILITIES (A)")
        for a in data.get('abilities', []):
            print(f"   [{a.get('id')}] {a.get('description')}")

        print("-" * 60)
        print(">> TASKS (T)")
        for t in data.get('tasks', []):
            print(f"   [{t.get('id')}] {t.get('description')}")
        print("-" * 60)
        print(">> NICE FRAMEWORK")
        for n in data.get('nice_framework', []):
            print(f"   [{n.get('id')}] {n.get('name')}")

        print("-" * 60)
        print(f"JUSTIFICATION: {data.get('justification', '')}")
        print("="*60 + "\n")

    def _apply_focus_constraints(self, draft: Dict, focus: str) -> Dict:
        if not draft:
            return draft
        if focus == "mitre":
            for section in ["knowledge", "skills", "abilities", "tasks"]:
                draft[section] = []
        elif focus == "ksa":
            draft["mitre_attack"] = []
        return draft

# ==========================================
# MAIN
# ==========================================
if __name__ == "__main__":
    system = DeepResearchSystem()
    
    print("\n[SYSTEM ONLINE] Deep Research Agent (Hunter + Auditor Mode)")
    print("Type 'exit' to quit. Type 'file' to load input from a file.\n")

    while True:
        user_in = input("INPUT >> ")
        if user_in.lower() in ['exit', 'quit']:
            break

        if not user_in.strip():
            continue

        if user_in.strip().lower() == "file":
            file_input = system._read_user_file()
            if file_input:
                system.run(file_input)
            continue

        system.run(user_in)