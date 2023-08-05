import requests
import pdfkit
from final import util
from configparser import ConfigParser
import os

def read_var_from_conf(config_file, variable_to_read):
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

report_name = read_var_from_conf("glob.conf", "report_name")


# download html
response = requests.request("GET","http://127.0.0.1:5000/area_51_107")
util.mod_log("[+] Creating html file : html_response.html", util.OKCYAN)
with open("reports/html_response.html", "w") as file_obj:
    file_obj.write(response.text)

# html to pdf
pdf_file_name = "{}_report.pdf".format(report_name)
util.mod_log("[+] Converting to pdf", util.OKCYAN)
current_dir = os.getcwd()
os.chdir("reports")
pdfkit.from_file('html_response.html', pdf_file_name)
os.chdir(current_dir)

# kill the server
response = requests.request("GET", "http://127.0.0.1:5000/shutdown")
util.mod_log("[+] {}".format(response.text), util.OKCYAN)
