# phishing-detector
Phishing Detector Code Explanation
Required Tools

Python 3.x installed on your system
Access to a terminal or command prompt

Code Explanation
Step 1: Import required modules
pythonCopyimport re
import argparse

re: Python's regular expression module, used for pattern matching in strings
argparse: Used to parse command-line arguments

Step 2: Define the PhishingDetector class
pythonCopyclass PhishingDetector:
    def __init__(self):
        self.phishing_indicators = [
            # List of regular expressions for common phishing phrases and patterns
        ]

The class is initialized with a list of regular expressions that represent common phishing indicators

Step 3: Implement the analyze_email method
pythonCopydef analyze_email(self, subject, body):
    score = 0
    findings = []

    # Check subject and body for phishing indicators
    for indicator in self.phishing_indicators:
        if re.search(indicator, subject):
            score += 1
            findings.append(f"Suspicious subject: Matched '{indicator}'")
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

This method analyzes the email subject and body for phishing indicators
It increases the score and adds findings for each matched indicator
It also checks for mismatched URLs (where the displayed text doesn't match the actual URL)

Step 4: Implement the determine_risk method
pythonCopydef determine_risk(self, score):
    if score >= 5:
        return "High"
    elif score >= 3:
        return "Medium"
    elif score >= 1:
        return "Low"
    else:
        return "Safe"

This method determines the risk level based on the calculated score

Step 5: Implement the main function
pythonCopydef main():
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

The main function sets up command-line argument parsing
It creates a PhishingDetector instance and uses it to analyze the provided email
Finally, it prints the results

Step 6: Run the script
pythonCopyif __name__ == "__main__":
    main()

This block ensures the main function is only run if the script is executed directly (not imported as a module)

Steps to Run the Code

Save the code in a file named phishing_detector.py
Open a terminal or command prompt
Navigate to the directory containing the script
Run the script with the following command:
Copypython phishing_detector.py "Urgent: Account Verification Required" "Dear user, we have detected unusual activity on your account. Please click here to verify your identity: http://bit.ly/suspicious-link"
Replace the subject and body with the actual email content you want to analyze.
The script will output the phishing risk level, score, and any findings.
