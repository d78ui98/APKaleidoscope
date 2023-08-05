import re
import requests
import json

class VerifyKeys(object):

    def check_slack_token(self, input):

        params = {'token':input,
                  'pretty':'1',
        }
        response = requests.post('https://slack.com/api/auth.test', params=params)
        result = response.json()
        print(result)
        if result['ok'] == True:
            return input
        else:
            return "invalid"
    #print(check_slack_token("xoxb-1075004303153-1844697545025-BeMUv8EJXGMb8HTihRnHLS06"))

    def check_slack_webhook(self, input):

        headers = {
        'Content-type': 'application/json',
        }
        data = '{"text":""}'
        response = requests.post(input, headers=headers, data=data)
        if response.text == "no_text":
            return input
        else:
            return "invalid"
    #print(check_slack_webhook("https://hooks.slack.com/services/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"))

    def check_heroku(self, input):
        headers = {
        'Accept': 'application/vnd.heroku+json; version=3',
        'Authorization': 'Bearer {}'.format(input),
        }

        response = requests.post('https://api.heroku.com/apps', headers=headers)
        result = response.json()
        if result['id'] == 'unauthorized':
            return 'invalid'
        else:
            return input
    #print(check_heroku('1'))

    def check_mailgun(self, input):
        response = requests.get('https://api.mailgun.net/v3/domains', auth=('api', input))
        result = response.json()
        if result["message"] == "Invalid private key":
            return 'invalid'
        else:
            return input

    def check_stripe_live_token(self, input):
        response = requests.get('https://api.stripe.com/v1/charges', auth=("token_here", input))
        if response.ok:
            return input
        else:
            return 'invalid'
    #print(check_stripe_live_token('sk_test_4eC39HqLyjWDarjtT1zdp7dc'))

    def check_square_auth(self, input):
        headers = {
        'Authorization': 'Bearer [{}]'.format(input),
        }
        response = requests.get('https://connect.squareup.com/v2/locations', headers=headers)
        result = response.json()
        if "errors" in result.keys():   
            return 'invalid'
        else:
            return input

    #print(check_square_auth('abc'))

    #print(check_mailgun("key-wetrghnfdfgthfdfrghjmhgfdghmjyghfdf"))

    # def check_google_captcha(input):
    #     data = {"secret":input, "response":""}
    #     response = requests.post("https://www.google.com/recaptcha/api/siteverify", data=data)
    #     return response.json()
    # print(check_google_captcha("6Lasdfgasdfgasdfgasdfgasdfgasdfgasdfgasdf"))
    
    # def check_twilio(self, input):
    #     response = requests.get('https://api.twilio.com/2010-04-01/Accounts.json', auth=('ACCOUNT_SID', input))
    #     result = response.json()
    #     if result['status'] == 401:
    #         return "invalid"
    #     elif result['status'] == 200:
    #         return input
    #     else:
    #         return "invalid"

    # def check_facebook_access_token(self, input):
    #     response = requests.get("https://developers.facebook.com/tools/debug/accesstoken/?access_token={}&version=v3.2".format(input))
    #     return response.text

    #print(action_facebook_access_token("EAACEdEose0cBA0+"))

# x=VerifyKeys()
# x=x.check_slack_token("xoxb-1075004303153-1844697545025-BeMUv8EJXGMb8HTihRnHLS06")
# print(x)