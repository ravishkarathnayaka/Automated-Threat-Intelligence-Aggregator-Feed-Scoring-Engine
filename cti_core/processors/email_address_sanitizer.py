"""Phishing sender email address defanger/refanger and lookalike domain parser."""

import re
from typing import Dict, Optional


class EmailSanitizer:
    """Sanitizes and deconstructs phishing sender email addresses and reply-to headers."""

    EMAIL_REGEX = re.compile(r"^([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)$")

    @classmethod
    def refang_email(cls, email_str: str) -> str:
        """Refang defanged email address (e.g. user[at]domain[.]com)."""
        clean = email_str.strip()
        clean = re.sub(r"\[\s*at\s*\]|\(\s*at\s*\)|@at@", "@", clean, flags=re.IGNORECASE)
        clean = re.sub(r"\[\s*dot\s*\]|\(\s*dot\s*\)", ".", clean, flags=re.IGNORECASE)
        clean = clean.replace("[.]", ".").replace("(.)", ".")
        return clean.strip().lower()

    @classmethod
    def parse_email(cls, email_str: str) -> Optional[Dict[str, str]]:
        """Validate and deconstruct email into mailbox and sender domain."""
        refanged = cls.refang_email(email_str)
        match = cls.EMAIL_REGEX.match(refanged)
        if not match:
            return None

        local_part = match.group(1)
        domain = match.group(2)

        return {
            "full_email": refanged,
            "mailbox": local_part,
            "sender_domain": domain,
        }
