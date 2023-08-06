
# APKaleidoscope

APKaleidoscope is a Python based tool designed to scan Android applications (APK files) for security vulnerabilities. It specifically targets the OWASP Top 10 vulnerabilities, providing an easy and efficient way for developers, penetration testers, and security researchers to assess the security posture of Android apps.

![image](https://github.com/d78ui98/APKaleidoscope/assets/27950739/5715bed9-c916-43e4-af04-65e677b89e89)

## Features

APKaleidoscope is a Python-based tool that performs various operations on APK files. Its main features include:

- **APK Analysis**: Scans Android application package (APK) files for security vulnerabilities.
- **OWASP Coverage**: Covers OWASP Top 10 vulnerabilities to ensure a comprehensive security assessment.
- **Advanced Detection**: Utilizes Androguard for APK file analysis and vulnerability detection.
- **Sensitive Information Extraction**: Identifies potential security risks by extracting sensitive information from APK files, such as insecure authentication/authorization keys and insecure request protocols.
- **In-depth Analysis**: Detects insecure data storage practices, incuding data related to the SD card, and highlights the use of insecure request protocols in the code.
- **Report Generation**: Generates detailed and easy-to-understand reports for each scanned APK, providing actionable insights for developers.
- **CI/CD Integration**: Designed for easy integration into CI/CD pipelines, enabling automated security testing in development workflows.
- **User-Friendly Interface**: Color-coded terminal outputs make it easy to distinguish between different types of findings.
- **False Positive Handling**: Employs a list of known false positives to minimize incorrect detections and improve the accuracy of results.

## Installation

To use APKaleidoscope, you'll need to have Python 3.8 or higher installed on your system. You can then install it using the following command:

```
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

## Usage

The script can be run with one optional argument that specifies the APK file or link to be analyzed.

```
python APKaleidoscope.py file.apk
```
This will start the scanning process. Once completed, a detailed report will be generated and printed to the console.

## Contributing

We welcome contributions to the APKaleidoscope project! If you have a feature request, bug report, or proposal, please open a new issue on our GitHub page.

For those interested in contributing code, please follow the standard GitHub process: fork this repository, make your changes, and then submit a pull request. We'll review your contributions as quickly as possible.


