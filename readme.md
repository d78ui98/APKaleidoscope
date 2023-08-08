# <div align="center">APKaleidoscope</div>
<div align="center">
<a href="https://github.com/d78ui98/APKaleidoscope/tree/master#features">Features</a> • 
<a href="https://github.com/d78ui98/APKaleidoscope/tree/master#installation">Installation</a> • 
<a href="[docs/documentation.md](https://github.com/d78ui98/APKaleidoscope/blob/master/CHANGELOG.md)">Changlog</a>
</div>
<p>

APKaleidoscope is a Python based tool designed to scan Android applications (APK files) for security vulnerabilities. It specifically targets the OWASP Top 10 vulnerabilities, providing an easy and efficient way for developers, penetration testers, and security researchers to assess the security posture of Android apps.

![image](https://github.com/d78ui98/APKaleidoscope/assets/27950739/9d4087a1-5559-4a62-bf07-97e90c38f694)

## Features

APKaleidoscope is a Python-based tool that performs various operations on APK files. Its main features include:

- **APK Analysis** -> Scans Android application package (APK) files for security vulnerabilities.
- **OWASP Coverage** -> Covers OWASP Top 10 vulnerabilities to ensure a comprehensive security assessment.
- **Advanced Detection** -> Utilizes Androguard for APK file analysis and vulnerability detection.
- **Sensitive Information Extraction** -> Identifies potential security risks by extracting sensitive information from APK files, such as insecure authentication/authorization keys and insecure request protocols.
- **In-depth Analysis** -> Detects insecure data storage practices, including data related to the SD card, and highlights the use of insecure request protocols in the code.
- **Intent Filter Exploits** -> Pinpoint vulnerabilities by analyzing intent filters extracted from AndroidManifest.xml.
- **Local File Vulnerability Detection** -> Safeguard your app by identifying potential mishandlings related to local file operations
- **Report Generation** -> Generates detailed and easy-to-understand reports for each scanned APK, providing actionable insights for developers.
- **CI/CD Integration** -> Designed for easy integration into CI/CD pipelines, enabling automated security testing in development workflows.
- **User-Friendly Interface** -> Color-coded terminal outputs make it easy to distinguish between different types of findings.

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
python3 APKaleidoscope.py -apk file.apk
```
This will start the scanning process. Once completed, a detailed report will be generated and printed to the console.

If you have source code already extracted you can pass `-source` path. 

```
python3 APKaleidoscope.py -apk file.apk -source <source-code-path>
```
This will reduce the scan time. Helping you to get the output results faster.
## Contributing

We welcome contributions to the APKaleidoscope project. If you have a feature request, bug report, or proposal, please open a new issue [here](https://github.com/d78ui98/APKaleidoscope/issues).

For those interested in contributing code, please follow the standard GitHub process.
We'll review your contributions as quickly as possible :)


