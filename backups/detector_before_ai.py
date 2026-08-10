import base64
import re
import unicodedata
from dataclasses import dataclass, field


@dataclass
class DetectionResult:
    score: int
    action: str
    threat_types: list[str] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)
    explanations: list[str] = field(default_factory=list)


class PromptInjectionDetector:

    def __init__(self):
        self.rules = [
            {
                "name": "instruction_override",
                "category": "DIRECT_INJECTION",
                "pattern": r"\b(ignore|disregard|forget|override)\b.{0,80}\b(previous|prior|above|earlier)\b.{0,50}\b(instructions?|rules?|policy)\b",
                "score": 40,
                "explanation": (
                    "The prompt attempts to override previously established "
                    "instructions or security rules."
                ),
            },
            {
                "name": "system_prompt_extraction",
                "category": "PROMPT_EXTRACTION",
                "pattern": (
                    r"\b(reveal|show|print|display|tell me|give me|"
                    r"provide|expose)\b.{0,80}\b("
                    r"system prompt|system message|hidden prompt|"
                    r"hidden instructions|internal instructions|"
                    r"internal logic|source code|entire program|full code"
                    r")\b"
                ),
                "score": 45,
                "explanation": (
                    "The prompt attempts to obtain protected internal "
                    "instructions, system information, or implementation details."
                ),
            },
            {
                "name": "role_manipulation",
                "category": "ROLE_MANIPULATION",
                "pattern": (
                    r"\b(you are now|act as|pretend you are|"
                    r"roleplay as|assume the role of)\b"
                ),
                "score": 25,
                "explanation": (
                    "The prompt attempts to manipulate the AI into adopting "
                    "a different role or identity."
                ),
            },
            {
                "name": "jailbreak",
                "category": "JAILBREAK",
                "pattern": (
                    r"\b(dan|do anything now|jailbreak|"
                    r"developer mode|unrestricted mode)\b"
                ),
                "score": 45,
                "explanation": (
                    "The prompt contains language commonly associated with "
                    "jailbreak or unrestricted-operation attempts."
                ),
            },
            {
                "name": "security_bypass",
                "category": "SECURITY_BYPASS",
                "pattern": (
                    r"\b(disable|turn off|remove|bypass|evade|"
                    r"circumvent)\b.{0,100}\b("
                    r"security|filter|safety|restriction|restrictions|"
                    r"protection|guardrail|controls?)\b"
                ),
                "score": 40,
                "explanation": (
                    "The prompt attempts to circumvent or disable a "
                    "security control or safety boundary."
                ),
            },
            {
                "name": "fake_system_message",
                "category": "ROLE_MANIPULATION",
                "pattern": (
                    r"\b(system message|system instruction|system prompt)\s*:"
                ),
                "score": 35,
                "explanation": (
                    "The prompt attempts to impersonate a trusted system "
                    "or instruction message."
                ),
            },
            {
                "name": "delimiter_attack",
                "category": "CONTEXT_MANIPULATION",
                "pattern": (
                    r"(#{2,}|-{3,}|={3,}|\[system\]|\[assistant\]|\[user\])"
                ),
                "score": 25,
                "explanation": (
                    "The prompt contains delimiters or role markers that "
                    "may attempt to manipulate the model's context."
                ),
            },
        ]

    def analyze(self, prompt: str) -> DetectionResult:
        normalized = self._normalize(prompt)

        score_holder = [0]
        threat_types = []
        matched_rules = []
        explanations = []

        # 1. Normal rule-based detection
        self._apply_rules(
            normalized,
            score_holder,
            threat_types,
            matched_rules,
            explanations,
        )

        score = score_holder[0]

        # 2. Behavioral analysis
        behavior_explanations = self._analyze_behavior(normalized)

        for explanation in behavior_explanations:
            if explanation not in explanations:
                explanations.append(explanation)

        # Convert behavioral signals into a security decision
        if behavior_explanations:
            if "PROMPT_EXTRACTION" not in threat_types:
                threat_types.append("PROMPT_EXTRACTION")

            if "behavioral_analysis" not in matched_rules:
                matched_rules.append("behavioral_analysis")

            # Behavioral requests for internal/protected information
            # should never remain ALLOW.
            score = max(score, 45)
        # 3. Base64 encoded payload detection
        decoded = self._decode_base64(prompt)

        if decoded:
            decoded_score_holder = [0]

            self._apply_rules(
                decoded,
                decoded_score_holder,
                threat_types,
                matched_rules,
                explanations,
            )

            if decoded_score_holder[0] > 0:
                score = max(score, 30)

                if "ENCODED_INJECTION" not in threat_types:
                    threat_types.append("ENCODED_INJECTION")

                if "base64_payload" not in matched_rules:
                    matched_rules.append("base64_payload")

                encoded_explanation = (
                    "The prompt contains Base64-encoded content that "
                    "decodes to suspicious instruction-like content."
                )

                if encoded_explanation not in explanations:
                    explanations.append(encoded_explanation)

        # 4. Limit score
        score = min(score, 100)

        # 5. Decide action
        if (
            "delimiter_attack" in matched_rules
            and "DIRECT_INJECTION" not in threat_types
        ):
            action = "WARN"
        elif score >= 70:
            action = "BLOCK"
        elif score >= 30:
            action = "WARN"
        else:
            action = "ALLOW"

        return DetectionResult(
            score=score,
            action=action,
            threat_types=threat_types,
            matched_rules=matched_rules,
            explanations=explanations,
        )

    def _apply_rules(
        self,
        text: str,
        score_holder: list[int],
        threat_types: list[str],
        matched_rules: list[str],
        explanations: list[str],
    ):
        for rule in self.rules:
            if re.search(rule["pattern"], text, re.IGNORECASE):

                score_holder[0] += rule["score"]

                if rule["category"] not in threat_types:
                    threat_types.append(rule["category"])

                if rule["name"] not in matched_rules:
                    matched_rules.append(rule["name"])

                explanation = rule.get("explanation")

                if explanation and explanation not in explanations:
                    explanations.append(explanation)

    @staticmethod
    def _decode_base64(text: str) -> str:
        compact = re.sub(r"\s+", "", text)

        if len(compact) < 16:
            return ""

        if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
            return ""

        try:
            padding = "=" * (-len(compact) % 4)

            decoded = base64.b64decode(
                compact + padding,
                validate=False,
            ).decode(
                "utf-8",
                errors="ignore",
            )

            if not decoded:
                return ""

            printable = sum(
                1
                for char in decoded
                if char.isprintable() or char.isspace()
            )

            if printable / len(decoded) < 0.80:
                return ""

            return PromptInjectionDetector._normalize(decoded)

        except Exception:
            return ""

    @staticmethod
    def _normalize(text: str) -> str:
        # Unicode compatibility normalization
        text = unicodedata.normalize("NFKC", text)

        # Remove zero-width/invisible characters
        text = re.sub(
            r"[\u200B\u200C\u200D\uFEFF]",
            "",
            text,
        )

        # Remove other Unicode format characters
        text = "".join(
            char
            for char in text
            if unicodedata.category(char) != "Cf"
        )

        # Lowercase
        text = text.lower()

        # Leetspeak normalization
        text = text.translate(
            str.maketrans(
                {
                    "0": "o",
                    "1": "i",
                    "3": "e",
                    "4": "a",
                    "5": "s",
                    "7": "t",
                }
            )
        )

        # Normalize whitespace
        text = re.sub(r"\s+", " ", text)

        # Restore common missing boundaries
        text = re.sub(
            r"(previous)(instructions)",
            r"\1 \2",
            text,
            flags=re.IGNORECASE,
        )

        return text.strip()

    @staticmethod
    def _analyze_behavior(text: str) -> list[str]:
        signals = []

        behavior_patterns = [
            (
                r"\b(reveal|show|print|display|give me|tell me|provide|share|"
                r"send|explain|describe)\b.{0,100}"
                r"\b(source code|entire program|full code|internal logic|"
                r"internal program|system prompt|hidden instructions|"
                r"internal instructions|implementation details)\b",
                "The prompt attempts to obtain protected internal information."
            ),
            (
                r"\b(internal|private|hidden|secret|confidential)\b.{0,80}"
                r"\b(program|code|logic|instructions|prompt|implementation)\b",
                "The prompt attempts to access internal or protected implementation information."
            ),
            (
                r"\b(ignore|disregard|forget|override)\b.{0,100}"
                r"\b(instructions|rules|policy|safety|security)\b",
                "The prompt attempts to override an existing security or instruction boundary."
            ),
            (
                r"\b(bypass|evade|circumvent|disable|remove)\b.{0,100}"
                r"\b(security|filter|restriction|safety|protection|guardrail)\b",
                "The prompt attempts to circumvent a security control or guardrail."
            ),
            (
                r"\b(do not tell|don't tell|hide this|keep this secret)\b",
                "The prompt contains language attempting to conceal its behavior."
            ),
        ]

        for pattern, explanation in behavior_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                if explanation not in signals:
                    signals.append(explanation)

        return signals
