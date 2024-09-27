import re
import argparse

class PhishingDetector:
    def __init__(self):
        self.phishing_indicators = [
            r"(?i)urgent action required",
            r"(?i)verify your account",
            r"(?i)update your information",
            r"(?i)click here to claim",
            r"(?i)your account will be suspended",
            r"(?i)unusual activity detected",
            r"(?i)login attempt from new device",
            r"(?i)confirm your identity",
            r"http://bit\.ly/\w+",
            r"https?://(?!www\.)[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/\S*)?",
        ]

    def analyze_email(self, subject, body):
        score = 0
        findings = []

        # Check subject
        for indicator in self.phishing_indicators:
            if re.search(indicator, subject):
                score += 1
                findings.append(f"Suspicious subject: Matched '{indicator}'")

        # Check body
        for indicator in self.phishing_indicators:
            if re.search(indicator, body):
                score += 1
                findings.append(f"Suspicious content: Matched '{indicator}'")

        # Check for mismatched URLs
        urls = re.findall(r'href=["\'](https?://[^\s\'"]+)["\']', body)
        for url in urls:
            display_text = re.findall(r'>([^<]+)</a>', body)
            if display_text and url not in display_text[0]:
                score += 2
                findings.append(f"Mismatched URL: Display text doesn't match actual URL")

        return score, findings

    def determine_risk(self, score):
        if score >= 5:
            return "High"
        elif score >= 3:
            return "Medium"
        elif score >= 1:
            return "Low"
        else:
            return "Safe"

def main():
    parser = argparse.ArgumentParser(description="Simple Phishing Email Detector")
    parser.add_argument("subject", help="Email subject")
    parser.add_argument("body", help="Email body")
    args = parser.parse_args()

    detector = PhishingDetector()
    score, findings = detector.analyze_email(args.subject, args.body)
    risk_level = detector.determine_risk(score)

    print(f"Phishing Risk Level: {risk_level}")
    print(f"Score: {score}")
    print("\nFindings:")
    for finding in findings:
        print(f"- {finding}")

if __name__ == "__main__":
    main()
#to the run the code in terminal:python phishing_detector.py "Urgent: Account Verification Required" "Dear user, we have detected unusual activity on your account. Please click here to verify your identity: http://bit.ly/suspicious-link"