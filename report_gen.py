import os
import subprocess
import re
import xml.etree.ElementTree as ET
import datetime
import logging
logging.basicConfig(level=logging.DEBUG, format="%(message)s")

"""
    Title:      APKaleidoscope
    Desc:       Android security insights in full spectrum.
    Author:     Deepanshu Gajbhiye
    Version:    1.0.0
    GitHub URL: https://github.com/d78ui98/APKaleidoscope/
"""

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

class ReportGen(object):

    def __init__(self, manifest, res_path, source_path, template_path):
        """
        Defining few important variables which are used throughout the class.
        """
        self.manifest = manifest
        self.res_path = res_path
        self.source_path = source_path
        self.template_path = template_path

    def render_template(self, template_name, datas, escape=False):
        """
        This method is used to render the template and relevant html data.

        """
        try:
            t_templates_str = {
                'report_template.html': self.load_template(self.template_path),
                'grep_lines.html': '<div><span class="grep_filepath">{{ filepath }}</span>:<span class="grep_line">{{ line }}</span>:{{ content }}</div>'
            }
            render = t_templates_str.get(template_name, "")
            if not render:
                util.mod_log(f"[-] ERROR: Template {template_name} not found.", util.FAIL)
                return ""

            for k, v in datas.items():
                if isinstance(v, list):
                    v = self.list_to_html(v)
                render = re.sub('{{\s*' + re.escape(k) + '\s*}}', v.replace('\\', '\\\\'), render)
            return render

        except Exception as e:
            util.mod_log(f"[-] ERROR in render_template: {str(e)}", util.FAIL)
            return ""

    def list_to_html(self, list_items):
        """
        This method is used to covert list to unordered list in html
        """
        try:
            if not isinstance(list_items, list):
                util.mod_log("[-] ERROR: The provided input is not a list.", util.FAIL)
                return ""
            items = [f"<li>{perm}</li>" for perm in list_items]
            return "<ul>" + "\n".join(items) + "</ul>"
        
        except Exception as e:
            util.mod_log(f"[-] ERROR in list_to_html: {str(e)}", util.FAIL)
            return ""


    def grenerate_html_report(self, report, html_report_path):
        """
        This method is used to generate a final html report which can be later converted to pdf
        """
        try:
            with open(html_report_path, 'w') as fp:
                fp.write(report)
            print("report generated")
        
        except Exception as e:
            util.mod_log(f"[-] ERROR in generate_html_report: {str(e)}", util.FAIL)

    def load_template(self, template_path):
        """
        read of the template.
        """
        try:
            with open(self.template_path) as f:
                return f.read()
        except Exception as e:
            util.mod_log(f"[-] ERROR in load_template: {str(e)}", util.FAIL)
            return ""


    def grep_keyword(self, keyword):
        """
        This function is used to read keyword dict and run the grep commands on the extracted android source code.

        """
        output = ''

        """
        This dictionary stores the keywords to search with the grep command.
        Grep is much much faster than re.
        ToDo -
        - Add more search keywords
        - move entire project to use grep.
        """
        keyword_search_dict = {
            'external_call': [
                '([^a-zA-Z0-9](OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|VERSION-CONTROL|REPORT|CHECKOUT|CHECKIN|UNCHECKOUT|MKWORKSPACE|UPDATE|LABEL|MERGE|BASELINE-CONTROL|MKACTIVITY|ORDERPATCH|ACL|PATCH|SEARCH|ARBITRARY)[^a-zA-Z0-9])',
                '(@(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|VERSION-CONTROL|REPORT|CHECKOUT|CHECKIN|UNCHECKOUT|MKWORKSPACE|UPDATE|LABEL|MERGE|BASELINE-CONTROL|MKACTIVITY|ORDERPATCH|ACL|PATCH|SEARCH|ARBITRARY)\()',
            ],
            'intent': ['(new Intent|new android\.content\.Intent|PendingIntent|sendBroadcast|sendOrderedBroadcast|startActivity|resolveActivity|createChooser|startService|bindService|registerReceiver)'],
            'internal_storage': ['(createTempFile|SQLiteDatabase|openOrCreateDatabase|execSQL|rawQuery)'],
            'external_storage': ['(EXTERNAL_STORAGE|EXTERNAL_CONTENT|getExternal)'],
        }
        if not keyword in keyword_search_dict:
            return ""

        for regexp in keyword_search_dict[keyword]:
            cmd = 'cd "' + self.res_path + '" ; grep -ErIn "' + regexp + '" "' + self.source_path + '" 2>/dev/null'
            #Eren yeager
            print(cmd)
            try:
                o = subprocess.check_output( cmd, shell=True ).decode('utf-8')
            except Exception as e:
                print(str(e))
                continue

            output = output + self.add_html_tag( o.strip(), regexp )

        return output

    def add_html_tag(self, grep_result, regexp):
        """
        This method is used add the html tags to grep output to color the output for better presentation
        """
        try:
            output = ''
            for grep in grep_result.split("\n"):
                tmp = grep.split(':')
                if len(tmp) < 3:  # Ensure there are enough components in the split result
                    continue
                filepath, line, content = tmp[0], tmp[1], ':'.join(tmp[2:])
                content = re.sub(regexp, 'ABRACADABRA1\\1ABRACADABRA2', content)
                output += self.render_template('grep_lines.html', {'filepath': filepath, 'line': line, 'content': content}, True)
                output = output.replace('ABRACADABRA1', '<span class="grep_keyword">').replace('ABRACADABRA2', '</span>')
            return output

        except Exception as e:
            util.mod_log(f"[-] ERROR in add_html_tag: {str(e)}", util.FAIL)
            return ""

    def get_build_information(self):
        """
        This method is used to get build information from android manifest.xml.
        """
        try:
            version = self.manifest.attrib.get('platformBuildVersionCode',
                                               self.manifest.attrib.get('compileSdkVersion', '?'))
            return version
        
        except Exception as e:
            util.mod_log(f"[-] ERROR in get_build_information: {str(e)}", util.FAIL)
            return "?"

    def extract_permissions(self, manifest):
        """
        This method is used to extract permissions from the android manifest.xml.
        """
        try:
            permissions = []
            for permission_elem in self.manifest.findall('.//uses-permission'):
                permission_name = permission_elem.attrib.get('android:name')
                if permission_name:
                    permissions.append(permission_name)
            return permissions
        
        except Exception as e:
            util.mod_log(f"[-] ERROR in extract_permissions: {str(e)}", util.FAIL)
            return []

    def extract_dangerous_permissions(self, manifest):
        """
        This method is used to extracts dangerous permissions from the android  manifest.xml.
        """
        permissions = []
        try:
            for permission_elem in self.manifest.findall('.//uses-permission'):
                permission_name = permission_elem.attrib.get('android:name')
                dangerous_permission_list = [
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
                if permission_name:
                    if permission_name in dangerous_permission_list:
                        permissions.append(permission_name)
            return permissions
        except Exception as e:
            util.mod_log(f"[-] ERROR in extract_dangerous_permissions: {str(e)}", util.FAIL)
            return []
