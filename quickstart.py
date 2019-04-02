from __future__ import print_function

import base64
import urllib
import httplib2
import os
import time, datetime
import json
import database
from bs4 import BeautifulSoup
import dateutil.parser as parser
from googleapiclient import discovery
from googleapiclient.errors import HttpError
from oauth2client import tools
from oauth2client.client import AccessTokenCredentials

try:
    import argparse
    flags = argparse.ArgumentParser(parents=[tools.argparser]).parse_args()
except ImportError:
    flags = None

store_dir=os.path.expanduser('~/ParsingEmail-Godr')
query = "movie OR sports OR lal"
label_id_one = 'INBOX'
#label_id_two = 'UNREAD'

def parse_mail(email,token):

    credentials = AccessTokenCredentials(token,'my-user-agent/1.0')
    http = httplib2.Http()
    http = credentials.authorize(http)
    service = discovery.build('gmail', 'v1', http=http)

    try:
        results = service.users().messages().list(userId=email, labelIds=[label_id_one], q=query).execute()
        if results['resultSizeEstimate'] != 0:
            mssg_list = results['messages']
            final_list = []
            for mssg in mssg_list:
                temp_dict = {}
                m_id = mssg['id']  # get id of individual message
                message = service.users().messages().get(userId=email, id=m_id).execute()  # fetch the message using API
                payld = message['payload']  # get payload of the message
                headr = payld['headers']  # get header of the payload

                for one in headr:  # getting the Subject
                    if one['name'] == 'Subject':
                        msg_subject = one['value']
                        temp_dict['Subject'] = msg_subject
                    else:
                        pass

                for two in headr:  # getting the date
                    if two['name'] == 'Date':
                        msg_date = two['value']
                        date_parse = (parser.parse(msg_date))
                        m_date = (date_parse.date())
                        temp_dict['Date'] = str(m_date)
                    else:
                        pass

                for three in headr:  # getting the Sender
                    if three['name'] == 'From':
                        msg_from = three['value']
                        temp_dict['Sender'] = msg_from
                    else:
                        pass

                temp_dict['Snippet'] = message['snippet']  # fetching message snippet

                try:
                # Fetching message body
                    mssg_parts = payld['parts']  # fetching the message parts
                    part_one = mssg_parts[0]  # fetching first element of the part
                    part_body = part_one['body']  # fetching body of the message
                    part_data = part_body['data']  # fetching data from the body
                    part_data1= payld['parts'][0]['body']['data']
                    clean_one = part_data1.replace("-", "+")  # decoding from Base64 to UTF-8
                    clean_one = clean_one.replace("_", "/")  # decoding from Base64 to UTF-8
                    clean_two = base64.b64decode(bytes(clean_one, 'UTF-8'))  # decoding from Base64 to UTF-8
                    soup= BeautifulSoup(clean_two, "lxml")
                    mssg_body = soup.body()
                    temp_dict['Message_body'] = mssg_body

                except:
                    pass

                temp_dict['Attachments'] = {}
                for part in message['payload']['parts']:
                    if part['filename']:

                        if 'data' in part['body']:
                            data = part['body']['data']
                        else:
                            att_id = part['body']['attachmentId']
                            att = service.users().messages().attachments().get(userId=email, messageId=m_id,
                                                                           id=att_id).execute()
                            data = att['data']
                            file_data = base64.urlsafe_b64decode(data.encode('UTF-8'))
                            path = os.path.join(store_dir, part['filename'])
                            with open(path, 'wb') as f:
                                f.write(file_data)
                        temp_dict['Attachments'][part['filename']] = att_id

                final_list.append(temp_dict)  # This will create a dictonary item in the final list
            return final_list

        else:
            return "No message with matching key words!"

    except HttpError as error:
        return 'An error occurred: %s' % error

def new_access_token(email):
    try:
        user = database.db.credentials.find_one({"email": email})
        params = {}
        params['client_id'] = user['client_id']
        params['client_secret'] = ''
        params['refresh_token'] = user['refresh_token']
        params['grant_type'] = 'refresh_token'
        request_url = "https://accounts.google.com/o/oauth2/token"

        response = urllib.request.urlopen(request_url, urllib.parse.urlencode(params).encode('utf-8')).read()
        current_ts = time.time()
        new_credentials = json.loads(response.decode('utf-8'))
        token_expiry_new = int(current_ts) + int(new_credentials['expires_in'])
        token_expiry_new_date = datetime.datetime.fromtimestamp(int(token_expiry_new)).strftime('%Y-%m-%d %H:%M:%S')
        new_access_token = new_credentials['access_token']
        print("New access token: ",new_access_token)
        database.db.credentials.update({'email': email}, {"$set": {'access_token': new_credentials['access_token'],
                                                                   'token_expiry':token_expiry_new_date}})
        try:
            parse_mail(email, new_access_token)
        except Exception as e:
            return "Exited in new_access_token function with exception: ", e

    except Exception as e:
        return 'An error occurred: %s' % e
