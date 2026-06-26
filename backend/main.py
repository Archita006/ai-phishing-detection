from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse as _urlparse
import joblib
import numpy as np
import pandas as pd
from feature_extractor import extract_features

app = FastAPI(title="Phishing Detection API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

model    = joblib.load("model/phishing_model.pkl")
features = joblib.load("model/features.pkl")

def parsed_domain(url): return _urlparse(url).netloc.lower()

class URLRequest(BaseModel):
    url: str

class ExplainRequest(BaseModel):
    url: str
    risk_score: float
    prediction: str
    red_flags: list[str]
    features: dict

@app.get("/")
def root():
    return {"status": "Phishing Detection API is running"}

@app.post("/analyze")
def analyze(req: URLRequest):
    feat_dict = extract_features(req.url)
    feat_vec  = pd.DataFrame([feat_dict])[features]

    prediction  = model.predict(feat_vec)[0]
    probability = model.predict_proba(feat_vec)[0]
    risk_score  = round(float(probability[1]) * 100, 2)

    red_flags = []
    if feat_dict['IsDomainIP']:                      red_flags.append("IP address used as domain")
    if feat_dict['IsHTTPS'] == 0:                    red_flags.append("No HTTPS")
    if feat_dict['HasObfuscation']:                  red_flags.append("Obfuscated characters detected")
    if feat_dict['NoOfSubDomain'] > 2:               red_flags.append("Excessive subdomains")
    if feat_dict['NoOfQMarkInURL'] > 1:              red_flags.append("Multiple query parameters")
    if feat_dict['URLLength'] > 75:                  red_flags.append("Unusually long URL")
    if feat_dict['DegitRatioInURL'] > 0.2:           red_flags.append("High ratio of digits in URL")
    if feat_dict['NoOfOtherSpecialCharsInURL'] > 10: red_flags.append("Many special characters")

    url_lower = req.url.lower()

    # IP address overrides
    if feat_dict['IsDomainIP']:
        risk_score = max(risk_score, 85.0)
    if feat_dict['IsDomainIP'] and feat_dict['IsHTTPS'] == 0:
        risk_score = max(risk_score, 92.0)

    # Obfuscation + no HTTPS
    if feat_dict['HasObfuscation'] and feat_dict['IsHTTPS'] == 0:
        risk_score = max(risk_score, 88.0)

    # Suspicious keywords in URL
    phishing_keywords = [
        'verify', 'secure', 'login', 'signin', 'account', 'update',
        'banking', 'confirm', 'password', 'credential', 'suspend',
        'unlock', 'validate', 'authorize', 'payment', 'invoice'
    ]
    keyword_hits = sum(1 for kw in phishing_keywords if kw in url_lower)
    if keyword_hits >= 2:
        risk_score = max(risk_score, 70.0)
    if keyword_hits >= 3:
        risk_score = max(risk_score, 85.0)

    # Suspicious TLDs
    suspicious_tlds = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.click', '.link']
    if any(url_lower.endswith(tld) or f'{tld}/' in url_lower for tld in suspicious_tlds):
        risk_score = max(risk_score, 75.0)

    # Brand impersonation
    brands = ['paypal', 'google', 'facebook', 'apple', 'amazon', 'microsoft', 'netflix', 'bank']
    for brand in brands:
        if brand in url_lower and f'www.{brand}.com' not in url_lower and f'{brand}.com' not in url_lower:
            risk_score = max(risk_score, 90.0)
            if "Brand impersonation detected" not in red_flags:
                red_flags.append("Brand impersonation detected")
            break

    # Credentials in URL
    if any(p in url_lower for p in ['user=', 'pass=', 'password=', 'pwd=']):
        risk_score = max(risk_score, 80.0)
        if "Credentials passed in URL" not in red_flags:
            red_flags.append("Credentials passed in URL")

    # Recalculate prediction based on final score
    prediction = 1 if risk_score >= 50 else 0

    return {
        "url":        req.url,
        "prediction": "phishing" if prediction == 1 else "legitimate",
        "risk_score": risk_score,
        "red_flags":  red_flags,
        "features":   feat_dict
    }

@app.post("/explain")
def explain(req: ExplainRequest):
    score = req.risk_score
    f     = req.features

    if score < 30:
        verdict = "This URL appears to be safe."
    elif score < 60:
        verdict = "This URL looks suspicious and should be treated with caution."
    else:
        verdict = "This URL is highly likely to be a phishing attempt."

    reasons = []
    if f.get("IsDomainIP"):                 reasons.append("it uses a raw IP address instead of a domain name")
    if not f.get("IsHTTPS"):                reasons.append("it lacks HTTPS encryption")
    if f.get("HasObfuscation"):             reasons.append("the URL contains obfuscated characters")
    if f.get("NoOfSubDomain", 0) > 2:      reasons.append("it has an unusual number of subdomains")
    if f.get("URLLength", 0) > 75:         reasons.append("the URL is abnormally long")
    if f.get("NoOfQMarkInURL", 0) > 1:     reasons.append("it contains multiple query parameters")
    if f.get("DegitRatioInURL", 0) > 0.2:  reasons.append("it has a high ratio of digits")

    if reasons:
        reason_str = "This is because " + ", and ".join(reasons) + "."
    else:
        reason_str = "No structural anomalies were found in the URL."

    if score >= 60:
        advice = "Do not enter any personal information, passwords, or payment details on this site."
    elif score >= 30:
        advice = "Verify the site through official channels before sharing any sensitive information."
    else:
        advice = "You can proceed, but always stay cautious and verify unfamiliar sites."

    return {"explanation": f"{verdict} {reason_str} {advice}"}