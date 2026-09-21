"""DOM Form & Credential Harvester Analyzer.

Safely parses HTML markup to detect password harvesting forms, external form action
targets, credit card input fields, and deceptive anti-analysis scripts.
Uses zero external dependencies (standard library HTMLParser).
"""

from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import List, Optional
from urllib.parse import urlparse


@dataclass
class FormAnalysisResult:
    """HTML form security inspection findings."""

    has_forms: bool = False
    has_password_field: bool = False
    has_credit_card_field: bool = False
    external_form_action: bool = False
    external_action_urls: List[str] = field(default_factory=list)
    is_credential_harvester: bool = False
    signals: List[str] = field(default_factory=list)


class _DOMSecurityParser(HTMLParser):
    """Zero-dependency standard library HTML parser for security form analysis."""

    def __init__(self, base_domain: str):
        super().__init__()
        self.base_domain = base_domain.lower()
        self.has_forms = False
        self.has_password_field = False
        self.has_credit_card_field = False
        self.external_form_action = False
        self.external_action_urls: List[str] = []
        self.signals: List[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]):
        attr_dict = {k.lower(): (v or "").lower() for k, v in attrs}

        if tag == "form":
            self.has_forms = True
            action = attr_dict.get("action", "")
            if action.startswith("http"):
                parsed = urlparse(action)
                action_host = (parsed.hostname or "").lower()
                if action_host and action_host != self.base_domain:
                    self.external_form_action = True
                    self.external_action_urls.append(action)
                    self.signals.append(f"Deceptive form submits credentials to external third-party domain: {action_host}")

        elif tag == "input":
            inp_type = attr_dict.get("type", "")
            inp_name = attr_dict.get("name", "")

            if inp_type == "password" or "pass" in inp_name:
                self.has_password_field = True
            if any(cc in inp_name for cc in ["cvv", "cvc", "cardnumber", "cc_num", "credit"]):
                self.has_credit_card_field = True


class FormAnalyzer:
    """Analyzes web page structure for phishing forms and credential harvesting."""

    @staticmethod
    def analyze_html(html: str, base_domain: str) -> FormAnalysisResult:
        """Inspect HTML DOM for credential collection inputs and external submission actions."""
        if not html:
            return FormAnalysisResult()

        parser = _DOMSecurityParser(base_domain)
        try:
            parser.feed(html)
        except Exception:
            pass

        if parser.has_password_field:
            parser.signals.append("Credential input field (<input type='password'>) detected")
        if parser.has_credit_card_field:
            parser.signals.append("Financial / Credit Card payment input detected")

        is_harvester = (parser.has_password_field or parser.has_credit_card_field) and (
            parser.external_form_action or parser.has_forms
        )

        return FormAnalysisResult(
            has_forms=parser.has_forms,
            has_password_field=parser.has_password_field,
            has_credit_card_field=parser.has_credit_card_field,
            external_form_action=parser.external_form_action,
            external_action_urls=parser.external_action_urls,
            is_credential_harvester=is_harvester,
            signals=parser.signals,
        )
