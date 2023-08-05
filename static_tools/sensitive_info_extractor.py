import os
import re

from .exploit_intent_filter import ExploitIntentFilter
from .verify_keys import VerifyKeys

# verify = VerifyKeys()
# def action():
#     return verify.check_slack_token("xoxb-1075004303153-1844697545025-BeMUv8EJXGMb8HTihRnHLS06")


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class SensitiveInfoExtractor(object):

    def get_all_file_paths(self, file_path):
        totalFiles = []
        for root, dirs, files in os.walk(file_path):
            tempFiles = [os.path.join(file_path,os.path.join(root, i)) for i in files]
            totalFiles += tempFiles

        return totalFiles 
    
    def extract_all_sensitive_info(self, list_of_files, relative_path):
        """
        This function detects M1: Insecure Authentication/Authorization
        Extracts all the keys for all the apk file
        in: file list - all file path
            relative - gives the path relative to this path
        Out: string path: key type: value
        """
        all_sensitive_info_list = []
        try:
            for file in list_of_files: # for each files
                read = open(file, "r", encoding='utf-8', errors='ignore').read() # read them
                types_ioc_list = self.extract(read) # and call extract function
                #fetching relative path
                real_relative_path = os.path.relpath(file, relative_path)
                for items in types_ioc_list:
                    print(items)
                    items = "{}: {}".format(real_relative_path, items)
                    all_sensitive_info_list.append(items)
            #return all_sensitive_info_list
        except Exception as e: # if it gives error
            return str(e) 
    
    def extract_insecure_request_protocol(self, list_of_files):
        """
        This function detects M2: Insecure Communication in OWASP Top 10
        It will check for all the insure communication used throughout the app source code.
        """
        final_list = list()
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(script_dir, 'known_false_positives.txt')
        # Read known false positives from a file
        with open(file_path, 'r') as f:
            known_false_positives = [line.strip() for line in f]
        for file in list_of_files:
            try:
                read = open(file, "r", encoding='utf-8', errors='ignore').read()
                regex_for_insecure_conn = "((?:http://|s?ftp://|smtp://|:javascript:|www\d{0,3}[.])[\w().=/;,#:@?&~*+!$%\{}-]+)"
                a = re.findall(regex_for_insecure_conn, read)
                for i in a:
                    # Only add to the list if it is not a known false positive
                    if not any(re.match(fp, i) for fp in known_false_positives):
                        final_list.append(i)
            except Exception as e:
                return str(e)
        return list(set(final_list))
    
    def extract(self, text):
        """
        This function is used to scan the given text for predefined patterns of sensitive information.
        Detected potential security issues in "{pattern_name}: {match}" format.
        """
        patterns = {
            "slack_token": "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
            "slack_webhook": "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
            "facebook_oauth": "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].{0,30}['\"\\s][0-9a-f]{32}['\"\\s]",
            "twitter_oauth": "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]",
            "twitter_access_token": "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
            "heroku_api": "[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
            "mailgun_api": "key-[0-9a-zA-Z]{32}",
            "mailchamp_api": "[0-9a-f]{32}-us[0-9]{1,2}",
            "picatic_api": "sk_live_[0-9a-z]{32}",
            "google_oauth_id": "[0-9(+-[0-9A-Za-z_]{32}.apps.googleusercontent.com",
            "google_api": "AIza[0-9A-Za-z-_]{35}",
            "google_captcha": "^6[0-9a-zA-Z_-]{39}$",
            "google_oauth": "ya29\\.[0-9A-Za-z\\-_]+",
            "amazon_aws_access_key_id": "AKIA[0-9A-Z]{16}",
            "amazon_mws_auth_token": "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "amazonaws_url": "s3\\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\\.s3\\.amazonaws.com",
            "facebook_access_token": "EAACEdEose0cBA[0-9A-Za-z]+",                                                                                                                
            "twilio_api_key": "\bSK[0-9a-fA-F]{32}\b",
            "twilio_account_sid": "\bAC[a-zA-Z0-9_\\-]{32}\b",
            "twilio_app_sid": "\bAP[a-zA-Z0-9_\\-]{32}\b",
            "paypal_braintree_access_token": "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
            "square_oauth_secret": "sq0csp-[ 0-9A-Za-z\\-_]{43}",
            "square_access_token": "sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}",
            "stripe_standard_api": "sk_live_[0-9a-zA-Z]{24}",
            "stripe_restricted_api": "rk_live_[0-9a-zA-Z]{24}",
            "github_access_token": "[a-zA-Z0-9_-]*:[a-zA-Z0-9_\\-]+@github\\.com*",
            "private_ssh_key": "-----BEGIN PRIVATE KEY-----[a-zA-Z0-9\\S]{100,}-----END PRIVATE KEY-----",
            "private_rsa_key": "-----BEGIN RSA PRIVATE KEY-----[a-zA-Z0-9\\S]{100,}-----END RSA PRIVATE KEY-----",
            "gpg_private_key_block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "generic_api_key": "[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
            "generic_secret": "[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
            "ip_address": r"(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)",
            "link_finder": "((?:https?://|s?ftps?://|file://|javascript:|www\d{0,3}[.])[\w().=/;,#:@?&~*+!$%\'{}-]+)",
            "password_in_url": "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]"
            }
        patterns = list(zip(patterns.keys(), patterns.values()))
        ioc_list = []

        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(script_dir, 'known_false_positives.txt')
        # Read known false positives from a file
        with open(file_path, 'r') as f:
            known_false_positives = [line.strip() for line in f]
        
        for p in patterns:
            res = list(set(re.findall(re.compile(p[1]), text)))  # try to find all patterns in text
            for i in res:
                # Only add to the list if it is not a known false positive
                if not any(re.match(fp, i) for fp in known_false_positives):
                    a="{}: {}".format(p[0],i)
                    ioc_list.append(a)
        return ioc_list

    def get_data_stored_on_sd_card(self, all_file_path):

        # Declaration
        object = ExploitIntentFilter()
        
        # code 
        result_list = []
        for file in all_file_path:
            if file.endswith(".java"):
                result = object.search_vulnerable_code(file, "-e getExternalStorageDirectory -e getExternalFilesDir")
                if len(result) > 0:
                    result_list.append(result)
        
        return result_list

        

#y=["/home/kali/Scripts/webapp_latest/app_source/orignal-smartplug.apk/resources/test.txt",  
#  "/home/kali/Scripts/webapp_latest/app_source/orignal-smartplug.apk/resources/connector.py"]
#y= SensitiveInfoExtractor().get_all_file_paths("/home/kali/webapp_latest/app_source/com.thewalleyapp.apk")
#print(y)
#asdf = SensitiveInfoExtractor().extract_insecure_request_protocol(y)
#print(asdf)



# for else condition
# y= SensitiveInfoExtractor().get_all_file_paths("/home/kali/webapp_latest/app_source/com.thewalleyapp.apk")
# x=SensitiveInfoExtractor().extract_all_sensitive_info(y, "/home/kali/webapp_latest/app_source")
# #data stored on sd card
# #x=SensitiveInfoExtractor().get_data_stored_on_sd_card(y)
# print(x)
 
