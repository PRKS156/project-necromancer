import requests
import json
from brain.signatures import CAUSE_TO_ACTION

def query_local_ai(profile, signature_hint):
    """
    Queries local Ollama using strict JSON output formats.
    Returns categorised cause variables paired with model probability confidence indicators.
    """
    url = "http://localhost:11434/api/generate"
    
    prompt = f"""
    You are a core network diagnostics utility. Analyze this network snapshot.
    SNAPSHOT: {json.dumps(profile)}
    HINT: {json.dumps(signature_hint)}
    
    You MUST output a valid JSON object matching exactly this layout:
    {{
       "predicted_cause": "Select from: DDOS_ATTACK, PORT_SCAN, ICMP_FLOOD, RESOURCE_EXHAUSTION, INTERFACE_DROP, UNKNOWN_ANOMALY",
       "confidence_score": 0.90
    }}
    """
    
    payload = {
        "model": "phi3",
        "prompt": prompt,
        "stream": False,
        "format": "json"  
    }
    
    try:
        response = requests.post(url, json=payload, timeout=30)
        if response.status_code == 200:
            ai_res = json.loads(response.json()["response"])
            cause = ai_res.get("predicted_cause", "UNKNOWN_ANOMALY")
            
            return {
                "root_cause": cause,
                "confidence_score": float(ai_res.get("confidence_score", 0.50)),
                "mapped_action": CAUSE_TO_ACTION.get(cause, "NONE")
            }
    except Exception:
        pass
        
    # LOGICAL BACKUP INTERPRETATION LAYER
    # If the local LLM server times out or fails to resolve, the engine defaults to a 
    # rule-only fallback configuration. We explicitly hardcode a confidence metric of 0.50 (50%)
    # here by design. This acts as a security feature: since 50% sits below our system's mandatory 
    # MIN_AI_CONFIDENCE gate (75%), it guarantees that uncorroborated, single-engine decisions 
    # are blocked from executing automated system mutations until an engineer manually reviews them.
    fallback_cause = signature_hint.get("cause", "UNKNOWN_ANOMALY")
    return {
        "root_cause": fallback_cause,
        "confidence_score": 0.50,  
        "mapped_action": CAUSE_TO_ACTION.get(fallback_cause, "NONE")
    }

def generate_incident_report(profile, signature_hint):
    """
    Queries local Ollama to generate a beautified Markdown report explaining the crash.
    """
    url = "http://localhost:11434/api/generate"
    
    prompt = f"""
    You are an expert cybersecurity analyst. A network anomaly just occurred.
    Analyze this network snapshot and write a comprehensive, easy-to-understand incident report in Markdown format.
    
    SNAPSHOT DATA: {json.dumps(profile)}
    INITIAL RULE HINT: {json.dumps(signature_hint)}
    
    The report should include:
    1. **Executive Summary**: A brief, simple explanation of what happened.
    2. **Root Cause Analysis**: Why did the crash happen? What do the metrics/packets indicate?
    3. **Key Data Observations**: Highlight 2-3 important metrics from the snapshot.
    4. **Recommended Actions**: How can we prevent this in the future?
    
    Make it sound professional but clear. Do not output JSON. Output strictly the Markdown report.
    """
    
    payload = {
        "model": "phi3",
        "prompt": prompt,
        "stream": False
    }
    
    try:
        response = requests.post(url, json=payload, timeout=300)
        if response.status_code == 200:
            return response.json()["response"]
    except Exception as e:
        return f"**Error generating report**: Could not connect to local AI. Ensure Ollama is running.\n\nDetails: {str(e)}"
    
    return "**Error**: Failed to generate report from local AI."
