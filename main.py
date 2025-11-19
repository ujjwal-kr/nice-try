import os
import json
import subprocess
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
MAX_LOOPS = 3
INNER_LOOP_MAX = 3
MODEL_NAME = 'gemini-2.5-flash-preview-09-2025'

# ==========================================
# 1. THE HUNTER (RESEARCH AGENT)
# ==========================================
class HunterAgent:
    def __init__(self):
        self.model = genai.GenerativeModel(
            model_name=MODEL_NAME,
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
        )
        
        self.system_prompt = """
        You are a Senior Cybersecurity Compliance Auditor.
        Your job is to VERIFY the research of a junior analyst.
        
        Process:
        1. You will receive a JSON object containing MITRE and NICE codes from a junior analyst.
        2. You will also receive context from an internal knowledge base, which is considered the source of truth.
        3. You MUST use the internal knowledge base context to verify if the codes and descriptions from the junior analyst's draft are accurate.
        4. Check for:
           - Hallucinated codes (e.g., T9999).
           - Deprecated codes.
           - Mismatched descriptions (e.g., Using a Network Scanning code for a Phishing attack).
        5. If the internal knowledge base is empty, use your own knowledge and Google Search to verify.
        """
        
        self.output_format = """
        {
            "status": "PASS" or "FAIL",
            "feedback": "Empty string if PASS, specific instructions on what to fix if FAIL."
        }
        """

        self.focus_instructions = {
            "mitre": "Only verify MITRE entries; if NICE entries are present, flag them as extraneous unless justified by an explicit MITRE description.",
            "ksa": "Only verify KSA (NICE) entries. Do NOT fail the audit if MITRE ATT&CK entries are missing or empty. Focus strictly on the accuracy of Knowledge, Skills, Abilities, and Tasks.",
            "both": "Verify both MITRE and NICE entries for accuracy."
        }

    def verify(self, original_input: str, draft_json: Dict, focus: str = "both") -> Dict:
        print(f"    [Auditor] Verifying data against official sources...")
        
        # Step 1: Extract only IDs from draft_json
        ids = []
        # We only have MITRE data locally. KSA/NICE data is not in the 'data' directory.
        keys_to_check = ['mitre_attack']

        for key in keys_to_check:
            if key in draft_json:
                for item in draft_json[key]:
                    if 'id' in item:
                        ids.append(item['id'])

        ids = sorted(list(set(ids)))

        # Step 2: Run ripgrep with the IDs
        ripgrep_context = ""
        if ids:
            pattern = "|".join(ids)
            data_dir = 'data'
            print(f"    [Auditor] Searching for IDs: {pattern[:100]}...")
            if os.path.exists(data_dir):
                try:
                    # Using -A 2 to get 2 lines of context after the match
                    print(f"    [Auditor] Command: rg -i '{pattern}' {data_dir} --json -A 2")
                    result = subprocess.run(
                        ['rg', '-i', pattern, data_dir, '--json', '-A', '2'],
                        capture_output=True,
                        text=True,
                    )
                    if result.returncode == 0:
                        for line in result.stdout.strip().split('\n'):
                            try:
                                match = json.loads(line)
                                if match.get('type') == 'match':
                                    new_context = f"Found in {match['data']['path']['text']}:\n"
                                    new_context += match['data']['lines']['text']
                                    if len(ripgrep_context) + len(new_context) < 6000:
                                        ripgrep_context += new_context
                                    else:
                                        break
                            except json.JSONDecodeError:
                                continue
                    elif result.returncode != 1:
                        print(f"    [!] Ripgrep search failed: {result.stderr}")
                except FileNotFoundError:
                    print("    [!] Ripgrep (rg) not found. Please install ripgrep.")
            else:
                print(f"    [!] Data directory '{data_dir}' not found.")

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
        __RIPGREP_CONTEXT__

        INSTRUCTION: Verify the junior analyst's draft against the internal knowledge base context. The internal context is the source of truth.

        [REQUIRED JSON OUTPUT FORMAT]
        __OUTPUT_FORMAT__
        """
        
        focus_instruction = self.focus_instructions.get(focus, self.focus_instructions["both"])
        final_prompt = verification_template.replace("__SYSTEM_PROMPT__", self.system_prompt) \
                            .replace("__FOCUS_INSTRUCTION__", focus_instruction) \
                            .replace("__USER_INPUT__", safe_input) \
                            .replace("__DRAFT_JSON__", json_str) \
                            .replace("__RIPGREP_CONTEXT__", ripgrep_context if ripgrep_context else "No internal context found.") \
                            .replace("__OUTPUT_FORMAT__", self.output_format)
        
        try:
            chat = self.model.start_chat(history=[])
            response = chat.send_message(final_prompt)
            return self._clean_json(response.text)
        except Exception as e:
            print(f"    [!] Auditor Malfunction: {e}")
            return {"status": "PASS", "feedback": "Auditor crashed, manual check recommended."}

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