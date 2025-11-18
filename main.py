import os
import json
import time
import google.generativeai as genai
from google.generativeai import protos, types
from dotenv import load_dotenv
from typing import Dict, List, Any

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
            "nice_framework": [
                {"id": "XX-XXX-XXX", "name": "Work Role Name"}
            ],
            "justification": "Why these codes match"
        }
        """

    def generate_draft(self, user_input: str, feedback: str = "", attempt: int = 1) -> Dict:
        print(f"    [Hunter] Executing research pass #{attempt}...")
        
        # Using .replace() instead of f-strings to avoid SyntaxErrors with braces
        prompt = """
        [SYSTEM]
        __SYSTEM_PROMPT__
        
        [USER INPUT]
        "__USER_INPUT__"
        
        [PREVIOUS FEEDBACK]
        __FEEDBACK__
        
        [REQUIRED JSON OUTPUT FORMAT]
        __OUTPUT_FORMAT__
        """
        
        safe_input = user_input.replace('"', "'")
        safe_feedback = feedback if feedback else "None - First Attempt"
        
        final_prompt = prompt.replace("__SYSTEM_PROMPT__", self.system_prompt) \
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
        1. You will receive a JSON object containing MITRE and NICE codes.
        2. You MUST use Google Search to verify if these codes actually exist and match the description.
        3. Check for:
           - Hallucinated codes (e.g., T9999).
           - Deprecated codes.
           - Mismatched descriptions (e.g., Using a Network Scanning code for a Phishing attack).
        """
        
        self.output_format = """
        {
            "status": "PASS" or "FAIL",
            "feedback": "Empty string if PASS, specific instructions on what to fix if FAIL."
        }
        """

    def verify(self, original_input: str, draft_json: Dict) -> Dict:
        print(f"    [Auditor] Verifying data against official sources...")
        
        json_str = json.dumps(draft_json, indent=2)
        safe_input = original_input.replace('"', "'")
        
        # Using .replace() to be safe
        verification_template = """
        [SYSTEM]
        __SYSTEM_PROMPT__
        
        [ORIGINAL USER ACTION]
        "__USER_INPUT__"
        
        [JUNIOR ANALYST DRAFT]
        __DRAFT_JSON__
        
        INSTRUCTION: verify the 'mitre_attack' IDs and 'nice_framework' IDs using Google Search.
        If they are incorrect or hallucinated, fail the audit.
        
        [REQUIRED JSON OUTPUT FORMAT]
        __OUTPUT_FORMAT__
        """
        
        final_prompt = verification_template.replace("__SYSTEM_PROMPT__", self.system_prompt) \
                                            .replace("__USER_INPUT__", safe_input) \
                                            .replace("__DRAFT_JSON__", json_str) \
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
        
        feedback = ""
        final_output = None
        
        for i in range(1, MAX_LOOPS + 1):
            print(f"\n--- LOOP {i}/{MAX_LOOPS} ---")
            
            # Step 1: Hunter generates draft
            draft = self.hunter.generate_draft(user_input, feedback, attempt=i)
            
            if not draft:
                feedback = "Previous JSON was invalid. Output strict JSON."
                print("    [!] Hunter returned empty/invalid JSON. Retrying...")
                continue

            # Step 2: Auditor verifies draft
            audit = self.auditor.verify(user_input, draft)
            
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

    def _print_report(self, original, data):
        if not data: return
        print("\n" + "="*60)
        print(" ✅ FINAL INTELLIGENCE REPORT")
        print("="*60)
        print(f"ORIGINAL: {original}")
        print(f"REFINED:  {data.get('refined_text', 'N/A')}")
        print("-" * 60)
        
        print(">> MITRE ATT&CK")
        for m in data.get('mitre_attack', []):
            print(f"   [{m.get('id')}] {m.get('name')}")

        print("-" * 60)
        print(">> NICE FRAMEWORK")
        for n in data.get('nice_framework', []):
            print(f"   [{n.get('id')}] {n.get('name')}")

        print("-" * 60)
        print(f"JUSTIFICATION: {data.get('justification', '')}")
        print("="*60 + "\n")

# ==========================================
# MAIN
# ==========================================
if __name__ == "__main__":
    system = DeepResearchSystem()
    
    print("\n[SYSTEM ONLINE] Deep Research Agent (Hunter + Auditor Mode)")
    print("Type 'exit' to quit.\n")

    while True:
        user_in = input("INPUT >> ")
        if user_in.lower() in ['exit', 'quit']:
            break
        
        if user_in.strip():
            system.run(user_in)