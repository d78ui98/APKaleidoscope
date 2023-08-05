import os
import subprocess
import sys
import re
import logging
import requests
import argparse
import time 
try:
    from configparser import ConfigParser
    from static_tools import sensitive_info_extractor
    from androguard import session, misc
except Exception as e:
    print(str(e))


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
{util.OKGREEN}██  ██ ██     ██ ██  ( (_| | | | (  __/| |( (_| |( (_) )\__, \( (__ ( (_) )| (_) )(  __/         {util.ENDC}
{util.OKGREEN}██  ██ ██     ██  ██ `\__,_)(___)`\___)(_)`\__,_)`\___/'(____/`\___)`\___/'| ,__/'`\___)         {util.ENDC}
{util.OKGREEN}                                                                           | |                   {util.ENDC}
{util.OKGREEN}                                                                           (_)                   {util.ENDC}
{util.OKCYAN}                                                                - By Deepanshu{util.ENDC}
        """
        print(logo)


# Check if in venv
try:
    os.environ['VIRTUAL_ENV']
except KeyError:
    util.mod_log("[-] ERROR: Not inside virtualenv. Do source venv/bin/activate", util.FAIL)
    exit(0)

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

    parser.add_argument("apk", metavar="APK", type=str, nargs="?",
                        help="Path to the APK file or link to be analyzed.")
    parser.add_argument("-v", "--version", action="version", version="AutoApkScanner v1.0",
                        help="Display the version of AutoApkScanner.")
    parser.add_argument("-l", "--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        default="INFO", help="Set the logging level. Default is INFO.")

    return parser.parse_args()


class AutoApkScanner(object):

    def __init__(self):
        pass

    def create_dir_to_extract(self, apk_file):
        '''
        Creating a folder to extract apk source code
        '''
        extracted_source_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app_source", apk_file)
        if os.path.exists(extracted_source_path) and os.path.isdir(extracted_source_path):
            util.mod_log("[+] Source code for apk - {} Already extracted. Skipping this step.".format(apk_file), util.OKCYAN)
            return {'result':0,"path":extracted_source_path}
        else:
            os.makedirs(extracted_source_path)
        util.mod_log("[+] Creating new directory for extracting apk : " + extracted_source_path, util.OKCYAN)
        return {'result':1,"path":extracted_source_path}
    
    def extract_source_code(self, apk_file, target_dir):
        '''
        Extracting source code with Jdax
        '''
        util.mod_log("[+] Extracting the source code to : "+target_dir, util.OKCYAN)
        output = subprocess.run(["static_tools/jadx/bin/jadx", apk_file, "-d", target_dir])
        print(output)
    
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
    
    def write_to_glob(self, to_write, variable_to_update):
        '''
        Write to global conf file
        '''

        config_file = "glob.conf"

        if os.path.isfile(config_file):

            # read conf file
            config_object = ConfigParser()
            config_object.read(config_file)
            path = config_object["ABS PATH"] #format for reading config file

            # Update conf file
            path[variable_to_update] = to_write

            # write changes to file
            with open(config_file, 'w') as conf:  #with is used to eliminate closing of file option format for opening config file
                config_object.write(conf)
            success_message = "Added Absolute path to {}".format(config_file)
            return success_message
        else:
            error_message = "Config file {} Not found".format(config_file)
            return error_message

if __name__ == "__main__":
    try:
        #import ipdb; ipdb.set_trace()
        parse_args()
        if len(sys.argv) <= 1:
            util.mod_log("[-] ERROR: Please enter apk file or apk link.", util.FAIL)
            exit(0)
        else:
            apk = sys.argv[1]
        
        apk_file = ""
        obj_self = AutoApkScanner()
        apk_file = apk
        apk_file_abs_path = obj_self.return_abs_path(apk_file)
        
        if not obj_self.apk_exists(apk_file):
            util.mod_log(f"[-] ERROR: {apk_file} not found in the current directory.", util.FAIL)
            exit(0)
        else:
            util.mod_print(f"[+] {apk_file} found!", util.OKGREEN)
        time.sleep(1)
        
        # Extracting source code
        target_dir = obj_self.create_dir_to_extract(apk_file)
        if target_dir["result"] == 0:
            target_dir = target_dir["path"]
            pass
        else:
            target_dir = target_dir["path"]
            obj_self.extract_source_code(apk_file_abs_path, target_dir)
    
        #Extracting abs path of extracted source code dir
        extracted_apk_path = obj_self.return_abs_path(target_dir)
    
        # abs path to config
        obj_self.write_to_glob(extracted_apk_path, "path")

        # apk file to conf
        dot_apk_file = obj_self.return_abs_path(apk_file)
        obj_self.write_to_glob(dot_apk_file, "apk_path")

        # writing apk name to conf
        obj_self.write_to_glob(apk_file, "report_name")
    
        #Extracting hardcoded secrets
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

        '''
        # Extracted data to html
        util.mod_log("[+] Writing extracted data to html template ", util.OKCYAN)
        current_dir = os.getcwd()
        os.chdir("static_tools")
        subprocess.run(["flask", "run"], env=dict(os.environ, FLASK_APP='serve-files.py'))
        subprocess.run(["python3", "-m", "flask", "run"])
        os.chdir(current_dir)
        '''
    except Exception as e:
        print(str(e))
        exit(0)
