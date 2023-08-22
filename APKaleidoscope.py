import os
import subprocess
import sys
import re
from weasyprint import HTML
import logging
import argparse
import time 
import datetime
import xml.etree.ElementTree as ET
from static_tools import sensitive_info_extractor
from report_gen import ReportGen
from configparser import ConfigParser

"""
    Title:      APKaleidoscope
    Desc:       Android security insights in full spectrum.
    Author:     Deepanshu Gajbhiye
    Version:    1.0.0
    GitHub URL: https://github.com/d78ui98/APKaleidoscope/
"""

logging.basicConfig(level=logging.DEBUG, format="%(message)s")

class util:
    '''
    A static class for which contain some useful variables and methods
    '''
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    def mod_print(text_output, color):
        print(color + "{}".format(text_output) + util.ENDC)

    def mod_log(text, color):
        logging.info(color + "{}".format(text) + util.ENDC)
    
    def print_logo():
        """
        Logo for apkaleidoscope
        """
        logo =f"""                 
{util.OKGREEN} ████  █████  ██  ██        (_ )        _     ( )                                                {util.ENDC}
{util.OKGREEN}██  ██ ██  ██ ██ ██    _ _   | |   __  (_)   _| |   _     ___   ___    _    _ _      __           {util.ENDC}
{util.OKGREEN}██████ █████  ████    /'_` ) | |  /'_`\| | /'_` | /'_`\ /',__) /'__) /'_`\ ( '_`\  /'_`\          {util.ENDC}
{util.OKGREEN}██  ██ ██     ██ ██  ( (_| | | | (  __/| |( (_| |( (_) )\__, \( (__ ( (_) )| (_) ||  __/         {util.ENDC}
{util.OKGREEN}██  ██ ██     ██  ██ `\__,_)(___)`\___)(_)`\__,_)`\___/'(____/`\___)`\___/'| ,__/'`\___)         {util.ENDC}
{util.OKGREEN}                                                                           | |                   {util.ENDC}
{util.OKGREEN}                                                                           (_)                   {util.ENDC}
{util.OKCYAN}                                              - Made By Deepanshu{util.ENDC}
        """
        print(logo)

def parse_args():
    """
    Parse command-line arguments.
    """
    util.print_logo()

    parser = argparse.ArgumentParser(
        description="{BOLD}{GREEN}APKaleidoscope:{ENDC} APK security insights in full spectrum. ".format(BOLD=util.BOLD, GREEN=util.OKCYAN, ENDC=util.ENDC),
        epilog="For more information, visit our GitHub repository.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("-apk", metavar="APK", type=str, required=True,
                    help="Path to the APK file to be analyzed.")
    parser.add_argument("-v", "--version", action="version", version="AutoApkScanner v1.0",
                        help="Display the version of AutoApkScanner.")
    parser.add_argument("-source_code_path", metavar="APK", type=str,
                    help="Enter a valid path of extracted source for apk.")
    parser.add_argument("-l", "--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        default="INFO", help="Set the logging level. Default is INFO.")
    parser.add_argument("--report", action="store_true", help="Generates a report if this argument is provided.")


    return parser.parse_args()
    


class AutoApkScanner(object):

    def __init__(self):
        pass

    def create_dir_to_extract(self, apk_file, extracted_path=None):
        '''
        Creating a folder to extract apk source code
        '''
        extracted_source_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app_source", apk_file)

        resources_path = os.path.join(extracted_source_path, "resources")
        sources_path = os.path.join(extracted_source_path, "sources")

        if os.path.exists(extracted_source_path) and os.path.isdir(extracted_source_path) and \
           os.path.exists(resources_path) and os.path.isdir(resources_path) and \
           os.path.exists(sources_path) and os.path.isdir(sources_path):
            util.mod_log("[+] Source code for apk - {} Already extracted. Skipping this step.".format(apk_file), util.OKCYAN)
            return {'result':0,"path":extracted_source_path}
        else:
            os.makedirs(extracted_source_path, exist_ok=True)
            util.mod_log("[+] Creating new directory for extracting apk : " + extracted_source_path, util.OKCYAN)
            return {'result':1,"path":extracted_source_path}
    
    def extract_source_code(self, apk_file, target_dir):
        '''
        Extracting source code with Jdax
        '''
        util.mod_log("[+] Extracting the source code to : "+target_dir, util.OKCYAN)
        
        is_windows = os.name == 'nt'
        jadx_executable = "jadx.bat" if is_windows else "jadx"
        jadx_path = os.path.join(os.getcwd(), "static_tools", "jadx", "bin", jadx_executable)
        output = subprocess.run([jadx_path, apk_file, "-d", target_dir])
        print(output)
    
    def extract_manifest_info(self, apk_file):
        """
        Extracts basic information from an Android Manifest file.
        """
        extracted_source_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app_source", apk_file)
        manifest_path = os.path.join(extracted_source_path, "resources", "AndroidManifest.xml")
        
        if not os.path.isfile(manifest_path):
            util.mod_log(f"[-] ERROR: Manifest file {manifest_path} not found.", util.FAIL)

        etparse = ET.parse(manifest_path)
        manifest = etparse.getroot()

        if not manifest:
            util.mod_log(f"[-] ERROR: Error parsing the manifest file for {apk_file}.", util.FAIL)

        android_namespace = '{http://schemas.android.com/apk/res/android}'

        data = {
        'platformBuildVersionCode': manifest.attrib.get('platformBuildVersionCode', "Not available"),
        'compileSdkVersion': manifest.attrib.get('compileSdkVersion', "Not available"),
        'permissions': [elem.attrib[f'{android_namespace}name'] for elem in manifest.findall('uses-permission')],
        'activities': [elem.attrib[f'{android_namespace}name'] for elem in manifest.findall('application/activity')],
        'services': [elem.attrib[f'{android_namespace}name'] for elem in manifest.findall('application/service')],
        'receivers': [elem.attrib[f'{android_namespace}name'] for elem in manifest.findall('application/receiver')],
        'providers': [elem.attrib[f'{android_namespace}name'] for elem in manifest.findall('application/provider')],
        'package_name': manifest.attrib.get('package', "Not available")
    }

        indent = "    "

        DANGEROUS_TYPES = [
            "android.permission.READ_CALENDAR",
            "android.permission.WRITE_CALENDAR",
            "android.permission.CAMERA",
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.GET_ACCOUNTS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_PHONE_NUMBERS",
            "android.permission.CALL_PHONE",
            "android.permission.ANSWER_PHONE_CALLS",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.ADD_VOICEMAIL",
            "android.permission.USE_SIP",
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.BODY_SENSORS",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_WAP_PUSH",
            "android.permission.RECEIVE_MMS",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
            "android.permission.READ_HISTORY_BOOKMARKS",
            "android.permission.WRITE_HISTORY_BOOKMARKS",
            "android.permission.INSTALL_PACKAGES",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.READ_LOGS",
            "android.permission.CHANGE_WIFI_STATE",
            "android.permission.DISABLE_KEYGUARD",
            "android.permission.GET_TASKS",
            "android.permission.BLUETOOTH",
            "android.permission.CHANGE_NETWORK_STATE",
            "android.permission.ACCESS_WIFI_STATE",
        ]
        dangerous_permissions = [perm for perm in data['permissions'] if perm in DANGEROUS_TYPES]

        util.mod_log(f"[+] Package Name:", util.OKCYAN)
        print(indent + data['package_name'] + "\n")

        util.mod_log(f"[+] Platform Build Version Code:", util.OKCYAN)
        print(indent + str(data['platformBuildVersionCode']) + "\n")

        util.mod_log(f"[+] Compile SDK Version:", util.OKCYAN)
        print(indent + str(data['compileSdkVersion']) + "\n")

        if data['permissions']:
            util.mod_log(f"[+] Permissions:", util.OKCYAN)
            for permission in data['permissions']:
                print(indent + permission)
            print()
        
        if dangerous_permissions:
            util.mod_log(f"[+] Dangerous Permissions:", util.FAIL)
            for permission in dangerous_permissions:
                print(indent + permission)
            print()

        if data['activities']:
            util.mod_log(f"[+] Activities:", util.OKCYAN)
            for activity in data['activities']:
                print(indent + activity)
            print()

        if data['services']:
            util.mod_log(f"[+] Services:", util.OKCYAN)
            for service in data['services']:
                print(indent + service)
            print()

        if data['receivers']:
            util.mod_log(f"[+] Receivers:", util.OKCYAN)
            for receiver in data['receivers']:
                print(indent + receiver)
            print()

        if data['providers']:
            util.mod_log(f"[+] Providers:", util.OKCYAN)
            for provider in data['providers']:
                print(indent + provider)
            print()

        return data

    def return_abs_path(self, path):
        '''
        Returns the absolute path
        '''
        return os.path.abspath(path)
    
    def apk_exists(self, apk_filename):
        '''
        Check if the apk file exists or not.
        '''
        return os.path.isfile(apk_filename)
    
    def convert_html_to_pdf(self, html_file, pdf_name):
        """
        Convert an HTML file to a PDF.
        """
        HTML(html_file).write_pdf(pdf_name)
    
    def clean_apk_name(self, apk_name):
        """
        This function removes 'com' and 'apk' parts from the apk_name if they exist.
        """
        cleaned_name = re.sub(r'(\.com|\.apk)', '', apk_name)
        return cleaned_name

if __name__ == "__main__":
    try:
        args = parse_args()

        # Check if virtual environment is activated.
        try:
            os.environ['VIRTUAL_ENV']
        except KeyError:
            util.mod_log("[-] ERROR: Not inside virtualenv. Do source venv/bin/activate", util.FAIL)
            exit(0)

        if not args.apk:
            util.mod_log("[-] ERROR: Please provide the apk file using the -apk flag.", util.FAIL)
            exit(0)

        apk = args.apk

        obj_self = AutoApkScanner()
        apk_file_abs_path = obj_self.return_abs_path(apk)
        if not obj_self.apk_exists(apk_file_abs_path):
            util.mod_log(f"[-] ERROR: {apk_file_abs_path} not found.", util.FAIL)
            exit(0)
        else:
            util.mod_print(f"[+] {apk_file_abs_path} found!", util.OKGREEN)
        time.sleep(1)
        
        # Extracting source code
        target_dir = obj_self.create_dir_to_extract(apk, extracted_path=args.source_code_path if args.source_code_path else None)
        if target_dir["result"] == 1:
            obj_self.extract_source_code(apk_file_abs_path, target_dir["path"])

        # Extracting abs path of extracted source code dir
        extracted_apk_path = obj_self.return_abs_path(target_dir["path"])

        # Extraction useful infomration from android menifest file
        obj_self.extract_manifest_info(apk)
    
        # Extracting hardcoded secrets
        obj = sensitive_info_extractor.SensitiveInfoExtractor()
        util.mod_log("[+] Reading all file paths ", util.OKCYAN)
        file_paths = obj.get_all_file_paths(extracted_apk_path)
        relative_to = extracted_apk_path
        util.mod_log("[+] Extracting all hardcoded secrets ", util.OKCYAN)
        obj.extract_all_sensitive_info(file_paths, relative_to)
    
        # extracting insecure connections
        util.mod_log("[+] Extracting all insecure connections ", util.OKCYAN)
        all_file_path = obj.get_all_file_paths(extracted_apk_path)
        result = obj.extract_insecure_request_protocol(all_file_path)
        print(result)

        ############## REPORT GENERATION #############

        if args.report:
            
            # Extracting all the required paths
            extracted_source_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app_source", apk)
            res_path = os.path.join(extracted_source_path, "resources")
            source_path = os.path.join(extracted_source_path, "sources")
            script_dir = os.path.dirname(os.path.abspath(__file__))
            template_path = os.path.join(script_dir, "report_template.html")

            try:
                # Reading the android manifest file.
                android_manifest_path = os.path.join(res_path, "AndroidManifest.xml")
                etparse = ET.parse(android_manifest_path)
                manifest = etparse.getroot()

                # Update the attributes by stripping out the namespace
                for elem in manifest.iter():
                    elem.attrib = {k.replace('{http://schemas.android.com/apk/res/android}', 'android:'): v for k, v in elem.attrib.items()}

                # Creating object for report generation module.
                obj = ReportGen(manifest, res_path, source_path, template_path)

                permissions  = obj.extract_permissions(manifest)
                dangerous_permission = obj.extract_dangerous_permissions(manifest)

                html_dict = {}
                html_dict['build'] = obj.get_build_information()
                html_dict['package_name'] = manifest.attrib['package']
                html_dict['android_version'] = manifest.attrib['android:versionCode']
                html_dict['date'] = datetime.datetime.today().strftime('%d/%m/%Y')
                html_dict['permissions'] = permissions
                html_dict['dangerous_permission'] = dangerous_permission
                html_dict['intent_grep'] = obj.grep_keyword('intent')
                html_dict['internal_storage_grep'] = obj.grep_keyword('internal_storage')
                html_dict['external_storage_grep'] = obj.grep_keyword('external_storage')
                #print(html_dict)

                # Ensure 'reports' directory exists
                if not os.path.exists('reports'):
                    os.makedirs('reports')

                # Generating the html report
                report_content = obj.render_template('report_template.html', html_dict)
                cleaned_apk_name = obj_self.clean_apk_name(apk)
                html_report_path = "reports/report_{}.html".format(cleaned_apk_name)
                obj.grenerate_html_report(report_content, html_report_path)
                util.mod_print("[+] Generated HTML report - {}".format(html_report_path), util.OKCYAN)

                # Converting html report to pdf.
                pdf_name = f"report_{cleaned_apk_name}.pdf"
                pdf_path = "reports/{}".format(pdf_name)
                obj_self.convert_html_to_pdf(html_report_path, pdf_path)
                util.mod_print("[+] Generated PDF report - {}".format(pdf_path), util.OKCYAN)

            except Exception as e:
                print(str(e))
        
    except Exception as e:
        util.mod_print(f"[-] {str(e)}", util.FAIL)
        exit(0)
