from flask import Flask, request, render_template, abort

from .sensitive_info_extractor import SensitiveInfoExtractor
from .exploit_intent_filter import ExploitIntentFilter
from configparser import ConfigParser
import os
import logging
logging.basicConfig(level=logging.DEBUG, format="%(message)s")

app = Flask(__name__)

class util:
    """
    A static class for which contain some useful variables and methods
    """
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    #@staticmethods
    def mod_print(text_output, color):
        print(color + "{}".format(text_output) + util.ENDC)

    def mod_log(text, color):
        logging.info(color + "{}".format(text) + util.ENDC)

def read_variable(config_file, variable_to_read):
    '''
    Function used to read to global conf file
    In : config file : Enter the path to config file
       : variable_to_read : Enter the variable to extract. Example apk_file
    Out : value of the variable to extract
    '''

    # Check if file is found
    if os.path.isfile(config_file):
        util.mod_log("[+] Found {} config file".format(config_file), util.OKCYAN)

        # read conf file
        config_object = ConfigParser()
        config_object.read(config_file)
        section_path = config_object["ABS PATH"]
        variable_value = section_path[variable_to_read]
        util.mod_log("[+] Extracted value for {}".format(variable_to_read), 
                                                            util.OKCYAN)
        return variable_value

    else:
        util.mod_log("[-] Unable to find {}".format(config_file), util.FAIL)
        error_message = "Not found"
        return error_message

def empty_variable(config_file, variable_to_empty):
    '''
    Function used to empty the variable in global conf file
    In : config file : Enter the path to config file
       : variable_to_empty : Enter the variable to empty. Example apk_file
    Out : value of the variable to extract
    '''
    # Check if file is found
    if os.path.isfile(config_file):

        # Creating object
        config_object = ConfigParser()
        config_object.read(config_file)
        section_path = config_object["ABS PATH"]

        # Empty the file
        section_path[variable_to_empty] = ""
        with open(config_file, 'w') as conf:
            config_object.write(conf)
        
        util.mod_log("[+] removed data from {}".format(config_file), util.OKCYAN)
        return "{} is now empty".format(variable_to_empty)
    else:
        util.mod_log("[-] Unable to find {}".format(config_file), util.FAIL)
        error_message = "Config file {} Not found".format(config_file)
        return error_message

try:
    # Reading from glob file
    path_from_config = "path"
    config_file = "../glob.conf"
    path_to_glob = read_variable("../glob.conf", path_from_config)
    
    # If config file not found
    if path_to_glob == "Not found":
        util.mod_log("[-] Unable to find {} file.".format(config_file), util.FAIL)
        exit(0)

    # Empty the variable 1
    variable_to_remove = path_from_config
    #empty_variable(config_file, variable_to_remove)

    # Extract insecure http reuests
    obj = SensitiveInfoExtractor()
    all_file_path = obj.get_all_file_paths(path_to_glob)
    result = obj.extract_insecure_request_protocol(all_file_path)
    print(result)
    data_on_sd_card = obj.get_data_stored_on_sd_card(all_file_path)

    # exploit intent filter
    ex_obj = ExploitIntentFilter()

    # read apk path
    apk_path_from_config = "apk_path"
    apk_file = read_variable(config_file, apk_path_from_config)

    # Empty the variable
    #empty_variable(config_file, apk_path_from_config)

    if apk_file == "":
        util.mod_log("[-] Unable to find apk file. Check config file.", util.FAIL)
        exit(0)
    
    # Extract data from andorid manifest xml
    android_manifest_xml_data = ex_obj.extract_from_androidmanifest_xml(apk_file)
    print(android_manifest_xml_data)
    #android_manifest_xml_data = {'android_version': {'Code': '10040', 'Name': '9.17.3.0'}, 'app_name': 'Aptoide', 'package_name': 'cm.aptoide.pt', 'uses_permission': [['android.permission.WAKE_LOCK', None], ['android.permission.READ_SYNC_STATS', None], ['com.android.launcher.permission.INSTALL_SHORTCUT', None], ['android.permission.RECEIVE_BOOT_COMPLETED', None], ['android.permission.INSTALL_PACKAGES', None], ['android.permission.CHANGE_WIFI_MULTICAST_STATE', None], ['android.permission.ACCESS_WIFI_STATE', None], ['android.permission.READ_SYNC_SETTINGS', None], ['android.permission.WRITE_SYNC_SETTINGS', None], ['android.permission.AUTHENTICATE_ACCOUNTS', None], ['android.permission.GET_ACCOUNTS', None], ['android.permission.MANAGE_ACCOUNTS', None], ['android.permission.INTERNET', None], ['android.permission.USE_CREDENTIALS', None], ['android.permission.READ_EXTERNAL_STORAGE', None], ['android.permission.WRITE_EXTERNAL_STORAGE', None], ['android.permission.CAMERA', None], ['android.permission.ACCESS_NETWORK_STATE', None], ['com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE', None]], 'permission': ['android.permission.INTERNET', 'com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE', 'com.android.launcher.permission.INSTALL_SHORTCUT', 'android.permission.GET_ACCOUNTS', 'android.permission.ACCESS_NETWORK_STATE', 'android.permission.WRITE_SYNC_SETTINGS', 'android.permission.MANAGE_ACCOUNTS', 'android.permission.RECEIVE_BOOT_COMPLETED', 'android.permission.READ_SYNC_SETTINGS', 'android.permission.ACCESS_WIFI_STATE', 'android.permission.USE_CREDENTIALS', 'android.permission.WAKE_LOCK', 'android.permission.CAMERA', 'android.permission.INSTALL_PACKAGES', 'android.permission.WRITE_EXTERNAL_STORAGE', 'android.permission.READ_EXTERNAL_STORAGE', 'android.permission.CHANGE_WIFI_MULTICAST_STATE', 'android.permission.AUTHENTICATE_ACCOUNTS', 'android.permission.READ_SYNC_STATS'], 'intent_filter_list': [{'cm.aptoide.pt.view.MainActivity': {'action': ['android.intent.action.MAIN'], 'category': ['android.intent.category.LAUNCHER']}}, {'com.facebook.CustomTabActivity': {'action': ['android.intent.action.VIEW'], 'category': ['android.intent.category.DEFAULT', 'android.intent.category.BROWSABLE']}}, {'cm.aptoide.pt.DeepLinkIntentReceiver': {'action': ['android.intent.action.VIEW'], 'category': ['android.intent.category.DEFAULT', 'android.intent.category.BROWSABLE']}}]}
    manifest_json = android_manifest_xml_data
    
    # Main function to execute
    # Return android_xml_findings
    # android_xml_findings = {
    #         "getString" : "",
    #         "getStringExtra" : "",
    #         "getExtras" : "",
    #         "xss_dectections" : "",
    #         "getData" : "",
    #         "getUrl" : "",
    #     }
    code_n_bug = ex_obj.main(manifest_json, path_to_glob)
    print(code_n_bug)


except Exception as e:
    print(str(e))

def shutdown_server():
    '''
    Action used to shutdown the flask rendering server
    '''
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()

@app.route('/area_51_107')
def files_to_html():
    try:
        return render_template("database.html", package_name=manifest_json["package_name"],
                                  apk_version=manifest_json["android_version"]["Name"],
                                  uses_permission =manifest_json["uses_permission"],
                                  name=result,
                                  getString=code_n_bug["getString"],
                                  getStringExtra=code_n_bug["getStringExtra"],
                                  getExtras=code_n_bug["getExtras"],
                                  xss_dectections=code_n_bug["xss_dectections"],
                                  getData=code_n_bug["getData"],
                                  getUrl=code_n_bug["getUrl"],
                                  data_on_sd_card=data_on_sd_card)
    except FileExistsError:
        abort(404)
    
@app.route('/shutdown', methods=['GET'])
def shutdown():
    shutdown_server()
    return 'Server shutting down...'
