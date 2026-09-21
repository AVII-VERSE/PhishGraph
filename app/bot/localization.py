"""Multi-Language Security Advisory and Verdict Localization.

Provides localized security advice in English, Hindi, and Spanish for non-technical users.
"""

from typing import Dict

MESSAGES: Dict[str, Dict[str, str]] = {
    "en": {
        "critical_title": "🚨 CRITICAL THREAT: DO NOT PROCEED",
        "critical_desc": "This link is strongly linked to credentials theft, phishing, or crypto wallet drainers. Do not enter passwords or sign transactions.",
        "high_title": "🔴 HIGH RISK: SUSPICIOUS PAGE",
        "high_desc": "Strong deception indicators detected. Exercise extreme caution and do not disclose sensitive information.",
        "moderate_title": "🟡 MODERATE RISK: CAUTION REQUIRED",
        "moderate_desc": "Unusual domain infrastructure or recent creation. Verify the official organization before trusting.",
        "low_title": "🟢 LOW RISK: NO ACTIVE THREAT DETECTED",
        "low_desc": "No prominent malicious indicators detected. Always ensure the address matches the official service.",
    },
    "hi": {
        "critical_title": "🚨 अत्यंत खतरनाक: कृपया आगे न बढ़ें!",
        "critical_desc": "यह लिंक पासवर्ड चोरी (फिशिंग) या क्रिप्टो वॉलेट खाली करने से जुड़ा हुआ है। इसमें कोई पासवर्ड या ओटीपी न डालें।",
        "high_title": "🔴 उच्च जोखिम: संदिग्ध वेबसाइट",
        "high_desc": "इस वेबसाइट में धोखाधड़ी के संकेत मिले हैं। अपनी कोई भी निजी या बैंकिंग जानकारी यहां दर्ज न करें।",
        "moderate_title": "🟡 मध्यम जोखिम: सावधानी बरतें",
        "moderate_desc": "यह डोमेन नया है या इसका सर्वर संदिग्ध है। आधिकारिक वेबसाइट की दोबारा जांच करें।",
        "low_title": "🟢 सुरक्षित: कोई सक्रिय खतरा नहीं मिला",
        "low_desc": "इस लिंक में कोई ज्ञात वायरस या फिशिंग रिकॉर्ड नहीं मिला। लॉगिन करने से पहले डोमेन स्पेलिंग जरूर जांचें।",
    },
    "es": {
        "critical_title": "🚨 AMENAZA CRÍTICA: NO CONTINÚE",
        "critical_desc": "Este enlace está fuertemente vinculado con robo de credenciales o estafas. No introduzca contraseñas.",
        "high_title": "🔴 ALTO RIESGO: SITIO SOSPECHOSO",
        "high_desc": "Se detectaron fuertes indicadores de suplantación. Tenga máxima precaución.",
        "moderate_title": "🟡 RIESGO MODERADO: PRECAUCIÓN REQUERIDA",
        "moderate_desc": "Infraestructura inusual o dominio registrado recientemente. Verifique antes de confiar.",
        "low_title": "🟢 BAJO RIESGO: SIN AMENAZA DETECTADA",
        "low_desc": "No se encontraron indicadores maliciosos. Asegúrese de que coincida con el servicio oficial.",
    },
}


def get_localized_verdict(risk_level: str, lang: str = "en") -> Dict[str, str]:
    """Retrieve title and description for a given risk level in requested language."""
    target_lang = lang.lower() if lang.lower() in MESSAGES else "en"
    risk_key = risk_level.lower()
    
    if risk_key == "critical":
        prefix = "critical"
    elif risk_key == "high":
        prefix = "high"
    elif risk_key == "moderate":
        prefix = "moderate"
    else:
        prefix = "low"

    return {
        "title": MESSAGES[target_lang][f"{prefix}_title"],
        "description": MESSAGES[target_lang][f"{prefix}_desc"],
    }
