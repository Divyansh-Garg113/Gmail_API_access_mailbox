from flask import Flask, request
import quickstart
import json
from flask.json import jsonify
import time, datetime
import database

app=Flask(__name__)

@app.route('/parse', methods=["POST"])
# This function saves the parameters in database against the email id of 
#user
def parsing():
    content = request.json
    em =database.db.credentials.find_one({'email':content['email']})
    if em is None:
        database.db.credentials.insert_one({"email":content['email'], "access_token":content['access_token'],
                                        "refresh_token": content['refresh_token'],"token_expiry":content['token_expiry'],
                                        "client_id":content['client_id'], "scopes":content['scopes']})
    mail = database.db.credentials.find_one({"email": content['email']})
    token_expiry = mail['token_expiry']
    token_expiry_ts = time.mktime(datetime.datetime.strptime(token_expiry, "%Y-%m-%d %H:%M:%S").timetuple())

    user_email = mail['email']
    token = mail['access_token']
    current_ts = time.time()
    if int(token_expiry_ts) > int(current_ts):
        return jsonify({'Emails': quickstart.parse_mail(user_email,token)})
    else:
        return jsonify({'Emails': quickstart.new_access_token(user_email)})

if __name__ == "__main__":
    app.run(debug=True)
