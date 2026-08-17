import re


class AIPromptAnalyzer:
    """
    Local semantic-style security analyzer.

    The analyzer looks for intent rather than relying on a single keyword.
    It combines:
      - instruction override detection
      - protected-information requests
      - prompt extraction
      - role manipulation
      - security bypass
      - unauthorized access
      - credential theft
      - harmful weapon-related requests
      - destructive/malicious intent
      - suspicious combinations of actions and targets
    """

    def analyze(self, prompt: str) -> dict:
        text = prompt.lower().strip()

        signals = []
        score = 0

        def add_signal(points, name):
            nonlocal score

            if name not in signals:
                signals.append(name)
                score += points

        # ---------------------------------------------------------
        # 1. Instruction override / jailbreak
        # ---------------------------------------------------------
        if re.search(
            r"\b(ignore|disregard|forget|override|replace|bypass)\b"
            r".{0,120}"
            r"\b(previous|prior|earlier|system|developer|instructions|"
            r"rules|policy|restrictions|safety)\b",
            text,
        ):
            add_signal(40, "instruction_override")

        # ---------------------------------------------------------
        # 2. Prompt / protected information extraction
        # ---------------------------------------------------------
        if re.search(
            r"\b(reveal|show|give|tell|provide|send|display|share|"
            r"expose|leak|extract)\b"
            r".{0,100}"
            r"\b(system prompt|hidden prompt|internal prompt|"
            r"hidden instructions|system instructions|internal code|"
            r"private information|confidential information|"
            r"secret information)\b",
            text,
        ):
            add_signal(45, "prompt_extraction")

        # ---------------------------------------------------------
        # 3. Protected/internal information
        # ---------------------------------------------------------
        if re.search(
            r"\b(get|obtain|access|give|send|provide|share|reveal|"
            r"extract|steal|leak)\b"
            r".{0,100}"
            r"\b(internal|private|hidden|secret|sensitive|confidential|"
            r"protected|restricted)\b"
            r".{0,100}"
            r"\b(code|logic|instructions|prompt|details|information|"
            r"data|files?)\b",
            text,
        ):
            add_signal(45, "protected_information_request")

        # ---------------------------------------------------------
        # 4. Role manipulation
        # ---------------------------------------------------------
        if re.search(
            r"\b(you are now|act as|pretend to be|become|imagine|"
            r"assume the role of|from now on you are)\b",
            text,
        ):
            add_signal(25, "role_manipulation")

        # ---------------------------------------------------------
        # 5. Security/filter bypass
        # ---------------------------------------------------------
        if re.search(
            r"\b(bypass|disable|remove|evade|circumvent|defeat|"
            r"get around|avoid)\b"
            r".{0,100}"
            r"\b(security|filter|restriction|safety|guardrail|"
            r"protection|moderation|firewall|policy|limit|block)\b",
            text,
        ):
            add_signal(50, "security_bypass")

        # ---------------------------------------------------------
        # 6. Unauthorized access / privilege escalation
        # ---------------------------------------------------------
        access_action = (
            r"(give|grant|provide|allow|enable|obtain|get|gain|"
            r"request|acquire)"
        )

        access_target = (
            r"(all|full|complete|unrestricted|unlimited|admin|"
            r"administrator|root|privileged|maximum)"
        )

        access_resource = (
            r"(access|control|permission|permissions|privilege|"
            r"privileges|authority|rights)"
        )

        if re.search(
            rf"\b{access_action}\b"
            r".{0,80}"
            rf"\b{access_target}\b"
            r".{0,60}"
            rf"\b{access_resource}\b",
            text,
        ):
            add_signal(50, "unauthorized_access_request")

        if re.search(
            rf"\b{access_target}\b"
            r".{0,50}"
            rf"\b{access_resource}\b",
            text,
        ) and re.search(
            r"\b(give|grant|obtain|get|gain|provide|allow|enable)\b",
            text,
        ):
            add_signal(50, "privilege_escalation")

        # ---------------------------------------------------------
        # 7. Credentials / secrets
        # ---------------------------------------------------------
        if re.search(
            r"\b(password|passwords|token|tokens|api key|apikey|"
            r"credential|credentials|secret key|authentication key|"
            r"private key|session cookie|access token)\b",
            text,
        ) and re.search(
            r"\b(give|show|reveal|find|get|obtain|steal|dump|"
            r"extract|send|provide|share|recover)\b",
            text,
        ):
            add_signal(60, "credential_request")

        # ---------------------------------------------------------
        # 8. Harmful weapon construction / acquisition
        # ---------------------------------------------------------
        weapon_terms = (
            r"(atomic bomb|nuclear bomb|nuclear weapon|chemical weapon|"
            r"biological weapon|explosive device|bomb|weapon|guns|granade|poison)"
        )

        harmful_actions = (
            r"(make|build|construct|create|assemble|manufacture|"
            r"design|develop|modify|obtain|acquire|detonate|weaponize)"
        )

        if re.search(rf"\b{harmful_actions}\b", text) and re.search(
            weapon_terms,
            text,
        ):
            add_signal(100, "harmful_weapon_request")

        # Direct instructional request involving a dangerous weapon.
        instructional_terms = (
            r"\b(how|how do i|how can i|instructions|steps|guide|"
            r"tutorial|method|procedure)\b"
        )

        if re.search(
            rf"{instructional_terms}.{{0,100}}{weapon_terms}",
            text,
        ):
            add_signal(100, "harmful_weapon_request")

        # Direct instructional request involving a dangerous weapon.
        if re.search(
            r"\b(how|how do i|how can i|instructions|steps|guide|"
            r"tutorial|method|procedure)\b"
            rf".{{0,100}}{weapon_terms}",
            text,
        ):
            add_signal(100, "harmful_weapon_request")

        # ---------------------------------------------------------
        # 9. Malicious/destructive actions
        # ---------------------------------------------------------
        destructive_actions = (
            r"(destroy|damage|disable|sabotage|delete|erase|"
            r"crash|disrupt|infect|attack|steal|exfiltrate)"
        )

        sensitive_targets = (
            r"(server|system|database|network|account|computer|"
            r"files|data|credentials|users)"
        )

        if re.search(rf"\b{destructive_actions}\b", text) and re.search(
            rf"\b{ sensitive_targets }\b".replace(" ", ""),
            text,
        ):
            add_signal(70, "malicious_action_request")

        # ---------------------------------------------------------
        # 10. Explicit unauthorized data access
        # ---------------------------------------------------------
        if re.search(
            r"\b(access|get|obtain|extract|download|dump|steal|"
            r"leak|exfiltrate)\b"
            r".{0,100}"
            r"\b(unauthorized|private|confidential|secret|"
            r"restricted|protected|stolen)\b",
            text,
        ):
            add_signal(60, "unauthorized_information_request")

        # ---------------------------------------------------------
        # 11. Suspicious combination:
        # action + protected target
        # ---------------------------------------------------------
        if re.search(
            r"\b(get|give|show|reveal|access|obtain|extract|send|"
            r"provide|share)\b",
            text,
        ) and re.search(
            r"\b(secret|sensitive|private|hidden|internal|"
            r"confidential|protected|restricted)\b",
            text,
        ):
            add_signal(45, "protected_resource_access")

        # ---------------------------------------------------------
        # Final risk calculation
        # ---------------------------------------------------------
        score = min(score, 100)

        if score >= 80:
            category = "CRITICAL"
        elif score >= 60:
            category = "HIGH"
        elif score >= 30:
            category = "MEDIUM"
        elif score > 0:
            category = "LOW"
        else:
            category = "NONE"

        return {
            "threat": score >= 30,
            "category": category,
            "risk": score,
            "reason": (
                "Suspicious semantic indicators detected: "
                + ", ".join(signals)
                if signals
                else "No suspicious semantic indicators detected."
            ),
        }
