"""
PII Pattern Detectors.

Stage 1: Pure regex matchers for personally identifiable information.
Return Candidate objects for classification in later stages.

Covers: email, phone, SSN, credit card, IPv4, IPv6, US street address.
"""

import re

from promptshield.detectors.base import BaseDetector
from promptshield.models import Candidate


class EmailDetector(BaseDetector):

    PATTERN = re.compile(
        r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"
    )
    PATTERN_NAME = "EMAIL_ADDRESS"

    def detect(self, text):
        candidates = []
        for match in self.PATTERN.finditer(text):
            value = match.group()
            local, _, domain = value.rpartition("@")
            if not local or not domain:
                continue
            if len(local) > 64:
                continue
            candidates.append(
                Candidate(
                    value=value,
                    start=match.start(),
                    end=match.end(),
                    pattern_name=self.PATTERN_NAME,
                )
            )
        return candidates


class PhoneDetector(BaseDetector):

    PATTERN = re.compile(
        r"(?:"
        r"\+1[\s.\-]?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}"
        r"|"
        r"\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}"
        r")"
    )
    PATTERN_NAME = "PHONE_NUMBER"
    EXCLUDE_EXACT = {
        "000-000-0000", "(000) 000-0000",
        "111-111-1111", "(111) 111-1111",
        "123-456-7890", "(123) 456-7890",
    }

    def detect(self, text):
        candidates = []
        for match in self.PATTERN.finditer(text):
            value = match.group()
            digits = re.sub(r"\D", "", value)
            if len(digits) == 11 and digits.startswith("1"):
                digits = digits[1:]
            if len(digits) != 10:
                continue
            if digits[:3] in ("000", "111", "555"):
                continue
            formatted = f"({digits[:3]}) {digits[3:6]}-{digits[6:]}"
            if formatted in self.EXCLUDE_EXACT:
                continue
            candidates.append(
                Candidate(
                    value=value,
                    start=match.start(),
                    end=match.end(),
                    pattern_name=self.PATTERN_NAME,
                )
            )
        return candidates


class SSNDetector(BaseDetector):

    PATTERN = re.compile(r"\b\d{3}[\s.\-]\d{2}[\s.\-]\d{4}\b")
    PATTERN_NAME = "SSN"

    def detect(self, text):
        candidates = []
        for match in self.PATTERN.finditer(text):
            value = match.group()
            digits = re.sub(r"\D", "", value)
            if len(digits) != 9:
                continue
            area = int(digits[:3])
            group = int(digits[3:5])
            serial = int(digits[5:])
            if area == 0 or area == 666 or area >= 900:
                continue
            if group == 0:
                continue
            if serial == 0:
                continue
            candidates.append(
                Candidate(
                    value=value,
                    start=match.start(),
                    end=match.end(),
                    pattern_name=self.PATTERN_NAME,
                )
            )
        return candidates


class CreditCardDetector(BaseDetector):

    PATTERN = re.compile(r"\b(?:\d[ \-]?){13,19}\b")
    PATTERN_NAME = "CREDIT_CARD"
    PREFIXES = {
        "4": "VISA",
        "51": "MASTERCARD", "52": "MASTERCARD", "53": "MASTERCARD",
        "54": "MASTERCARD", "55": "MASTERCARD",
        "34": "AMEX", "37": "AMEX",
        "6011": "DISCOVER",
        "35": "JCB",
    }

    def detect(self, text):
        candidates = []
        for match in self.PATTERN.finditer(text):
            value = match.group()
            digits = re.sub(r"\D", "", value)
            if len(digits) < 13 or len(digits) > 19:
                continue
            if not self._luhn_check(digits):
                continue
            network = self._identify_network(digits)
            if not network:
                continue
            candidates.append(
                Candidate(
                    value=value,
                    start=match.start(),
                    end=match.end(),
                    pattern_name=self.PATTERN_NAME,
                )
            )
        return candidates

    def _luhn_check(self, digits):
        total = 0
        reverse = digits[::-1]
        for i, d in enumerate(reverse):
            n = int(d)
            if i % 2 == 1:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
        return total % 10 == 0

    def _identify_network(self, digits):
        for prefix, network in sorted(self.PREFIXES.items(), key=lambda x: -len(x[0])):
            if digits.startswith(prefix):
                return network
        return None


class IPv4Detector(BaseDetector):

    PATTERN = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
    PATTERN_NAME = "IP_ADDRESS"

    def detect(self, text):
        candidates = []
        for match in self.PATTERN.finditer(text):
            octets = [int(match.group(i)) for i in range(1, 5)]
            if all(0 <= o <= 255 for o in octets):
                if octets[0] == 0:
                    continue
                candidates.append(
                    Candidate(
                        value=match.group(),
                        start=match.start(),
                        end=match.end(),
                        pattern_name=self.PATTERN_NAME,
                    )
                )
        return candidates


class IPv6Detector(BaseDetector):

    PATTERN = re.compile(
        r"\b([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"
    )
    PATTERN_NAME = "IPV6_ADDRESS"

    def detect(self, text):
        candidates = []
        for match in self.PATTERN.finditer(text):
            value = match.group()
            groups = value.split(":")
            if len(groups) < 3:
                continue
            if not all(len(g) <= 4 and all(c in "0123456789abcdefABCDEF" for c in g) for g in groups):
                continue
            if value == "::1" or value.startswith("::"):
                continue
            candidates.append(
                Candidate(
                    value=value,
                    start=match.start(),
                    end=match.end(),
                    pattern_name=self.PATTERN_NAME,
                )
            )
        return candidates


class USStreetAddressDetector(BaseDetector):

    PATTERN = re.compile(
        r"\b\d{1,5}\s+"
        r"(?:[A-Z][a-zA-Z]*\s+){1,3}"
        r"(?:St(?:reet)?|Ave(?:nue)?|Blvd|Boulevard|Dr(?:ive)?|Rd|Road|"
        r"Way|Ln|Lane|Ct|Court|Pl(?:ace)?|Pkwy|Parkway|Cir(?:cle)?)"
        r"\b"
        r"(?:\s*,?\s*[A-Z][a-zA-Z\s]+,?\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?)?",
        re.IGNORECASE,
    )
    PATTERN_NAME = "US_STREET_ADDRESS"

    def detect(self, text):
        candidates = []
        for match in self.PATTERN.finditer(text):
            value = match.group().strip()
            parts = value.split()
            if len(parts) < 3:
                continue
            if not parts[0].isdigit():
                continue
            num = int(parts[0])
            if num == 0 or num > 99999:
                continue
            candidates.append(
                Candidate(
                    value=value,
                    start=match.start(),
                    end=match.end(),
                    pattern_name=self.PATTERN_NAME,
                )
            )
        return candidates
