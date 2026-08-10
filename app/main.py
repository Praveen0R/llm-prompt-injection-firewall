from app.detector import PromptInjectionDetector
from app.logger import log_detection
from app.report import generate_report
from app.stats import show_stats


def print_result(result):
    print()
    print("======================================")
    print("        SECURITY ANALYSIS")
    print("======================================")
    print(f"Risk Score : {result.score}/100")
    print(f"Action     : {result.action}")

    print(
        f"Threats    : "
        f"{', '.join(result.threat_types) or 'NONE'}"
    )

    print(
        f"Rules      : "
        f"{', '.join(result.matched_rules) or 'NONE'}"
    )

    print()
    print("Explanation:")

    if result.explanations:
        for explanation in result.explanations:
            print(f"  - {explanation}")
    else:
        print("  - No suspicious behavior detected.")

    print("======================================")
    print()


def main():
    detector = PromptInjectionDetector()

    print("======================================")
    print("      LLM PROMPT INJECTION FIREWALL")
    print("======================================")
    print()
    print("Commands:")
    print("  stats  -> show security statistics")
    print("  report -> generate JSON report")
    print("  exit   -> quit firewall")
    print()

    while True:
        try:
            prompt = input("Prompt > ")

        except KeyboardInterrupt:
            print("\nExiting...")
            generate_report()
            break

        except EOFError:
            print("\nExiting...")
            generate_report()
            break

        command = prompt.strip().lower()

        if command == "exit":
            report = generate_report()

            print()
            print("Report generated:")
            print("  logs/report.json")
            print()
            print(
                f"Total prompts analyzed: "
                f"{report['total_prompts']}"
            )

            break

        if command == "stats":
            show_stats()
            continue

        if command == "report":
            report = generate_report()
            print()
            print("Report generated successfully.")
            print(f"Total Prompts : {report['total_prompts']}")
            print(f"Blocked       : {report['blocked']}")
            print(f"Warnings      : {report['warnings']}")
            print(f"Allowed       : {report['allowed']}")
            print()
            continue

        if not prompt.strip():
            print("Please enter a prompt.")
            continue

        result = detector.analyze(prompt)

        log_detection(prompt, result)

        print_result(result)


if __name__ == "__main__":
    main()
