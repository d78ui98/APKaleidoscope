import os
import subprocess
import re
import xml.etree.ElementTree as ET
import datetime

"""
    Title:      APKaleidoscope
    Desc:       Android security insights in full spectrum.
    Author:     Deepanshu Gajbhiye
    Version:    1.0.0
    GitHub URL: https://github.com/d78ui98/APKaleidoscope/
"""

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
        t_templates_str = {
        'report_template.html': self.load_template(self.template_path),
        'grep_lines.html': '<div><span class="grep_filepath">{{ filepath }}</span>:<span class="grep_line">{{ line }}</span>:{{ content }}</div>'
        }
        render = t_templates_str[template_name]
        for k,v in datas.items():
            if escape:
                pass
            if isinstance(v, list):
                v=self.list_to_html(v)
            render = re.sub('{{\s*'+k+'\s*}}', v, render)
        return render

    def list_to_html(self, list_items):
        """
        This method is used to covert list to unordered list in html
        """
        items = [f"<li>{perm}</li>" for perm in list_items]
        return "<ul>" + "\n".join(items) + "</ul>"


    def grenerate_html_report(self, report, html_report_path):
        """
        This method is used to generate a final html report which can be later converted to pdf
        """
        fp = open(html_report_path, 'w')
        fp.write(report)
        print("report generated")
        fp.close()

    def load_template(self, template_path):
        """
        read of the template.
        """
        f = open(self.template_path)
        result = f.read()
        f.close()
        return result


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
        output = ''

        for grep in grep_result.split("\n"):
            tmp = grep.split(':')
            filepath = tmp[0]
            line = tmp[1]
            content = ':'.join(tmp[2:])

            content = re.sub(regexp, 'ABRACADABRA1\\1ABRACADABRA2', content)

            output = output + self.render_template('grep_lines.html', {'filepath':filepath,'line':line,'content':content}, True)
            output = output.replace('ABRACADABRA1', '<span class="grep_keyword">' ).replace( 'ABRACADABRA2', '</span>')

        return output

    def get_build_information(self):
        """
        This method is used to get build information from android manifest.xml.
        """
        if 'platformBuildVersionCode' in self.manifest.attrib:
            version = self.manifest.attrib['platformBuildVersionCode']
        elif 'compileSdkVersion' in self.manifest.attrib:
            version = self.manifest.attrib['compileSdkVersion']
        else:
            version = '?'

        return version

    def extract_permissions(self, manifest):
        """
        This method is used to extract permissions from the android manifest.xml.
        """
        permissions = []
        for permission_elem in self.manifest.findall('.//uses-permission'):
            permission_name = permission_elem.attrib.get('android:name')
            if permission_name:
                permissions.append(permission_name)
        return permissions

    def extract_dangerous_permissions(self, manifest):
        """
        This method is used to extracts dangerous permissions from the android  manifest.xml.
        """
        permissions = []
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

if __name__ == "__main__":

    res_path = "/home/kali/Desktop/local/APKaleidoscope/app_source/com.thewalleyapp.apk/resources/"
    source_path = "/home/kali/Desktop/local/APKaleidoscope/app_source/com.thewalleyapp.apk/sources/"

    script_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = os.path.join(script_dir, "report_template.html")

    try:
        android_manifest_path = os.path.join(res_path, "AndroidManifest.xml")
        etparse = ET.parse(android_manifest_path)
        self.manifest = etparse.getroot()

        # update the attributes by stripping out the namespace
        for elem in self.manifest.iter():
            elem.attrib = {k.replace('{http://schemas.android.com/apk/res/android}', 'android:'): v for k, v in elem.attrib.items()}

        obj = ReportGen()

        permissions  = obj.extract_permissions(self.manifest)
        dangerous_permission = obj.extract_dangerous_permissions(self.manifest)

        html_dict = {}
        html_dict['build'] = obj.get_build_information()
        html_dict['package_name'] = self.manifest.attrib['package']
        html_dict['android_version'] = self.manifest.attrib['android:versionCode']
        html_dict['date'] = datetime.datetime.today().strftime('%d/%m/%Y')
        html_dict['permissions'] = permissions
        html_dict['dangerous_permission'] = dangerous_permission
        html_dict['intent_grep'] = obj.grep_keyword('intent')
        html_dict['internal_storage_grep'] = obj.grep_keyword('internal_storage')
        html_dict['external_storage_grep'] = obj.grep_keyword('external_storage')
        #print(html_dict)

        report = obj.render_template('report_template.html', html_dict)
        obj.grenerate_html_report(report)
    
    except Exception as e:
        print(str(e))