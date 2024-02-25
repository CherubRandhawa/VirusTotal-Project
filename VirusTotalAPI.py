# Importing necessary libraries
import os
import requests
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from json2html import json2html
import webbrowser
import smtplib
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

# Create the MongoDB client and database 
mongodb_username = os.getenv('MONGODB_USERNAME')
mongodb_password = os.getenv('MONGODB_PASSWORD')
mongodb_cluster = os.getenv('MONGODB_CLUSTER')
mongodb_database_name = os.getenv('MONGODB_DATABASE')

connected_string = f'mongodb+srv://{mongodb_username}:{mongodb_password}@{mongodb_cluster}/{mongodb_database_name}?retryWrites=true&w=majority'
client = MongoClient(connected_string)
virustotal_db = client.VirustotalFinal
stored_results_collection = virustotal_db.storedresults

def virus_total_scan(target_file, api_key):
    """
    Posts the file to Virus Total for Scanning using Virus Total API

    Parameters:
    - target_file: file to be scanned
    - api_key: to access virus total website

    Output:
    - returns the scan id so that we can check if this scan has happened before and if it is present in the database
    """

    virus_total_scan_api = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params_scan = {'apikey': api_key}

    with open(target_file, 'rb') as input_file:
        response_scan = requests.post(virus_total_scan_api, files={'file': input_file}, params=params_scan)
        scan_analysis = response_scan.json()

    scan_id = scan_analysis.get('scan_id')
    return scan_id

def retrieve_stored_result(scan_id):
    """
    This method retrieves stored results from mongo db collection 
    also creates an index with TTL of 24 hours

    Parameters:
    -scan_id: to look for reports in the database

    Output:
    - returns report according to scan id 
    """

    stored_results_collection.create_index('CreatedAt', expireAfterSeconds=86400)
    return stored_results_collection.find_one({'scanId': scan_id}, {'Report': 1})

def retrieve_report(scan_id, api_key):
    """
    This method retrieves results from Virus total 

    Parameters:
    - scan_id: retrieve report according to scan_id generated
    - api_key: to access virus total website

    Output:
    - Generates a report in the form of JSON
    """

    virus_total_report_api = 'https://www.virustotal.com/vtapi/v2/file/report'
    params_report = {'apikey': api_key, 'resource': scan_id}
    response_report = requests.get(virus_total_report_api, params=params_report)
    return response_report.json()


def virus_total(target_file, api_key):
    """
    If results are found in the database, they are displayed on the browser or else the report is retrieved, stored in the DB, and displayed on the web.

    Parameters:
    -target_file: file to be scanned
    -api_key: to access virsu total website

    Output:
    -Displays a report in the form of an HTML table on the web
    """
    scan_id = virus_total_scan(target_file, api_key)
    stored_result_retrieved = retrieve_stored_result(scan_id)

    if stored_result_retrieved:
        print('Your scan results are already present in the database')
        final_result = stored_result_retrieved['Report']
        write_to_html(final_result, 'result.html')
        webbrowser.open('result.html')
        return
    report = retrieve_report(api_key, scan_id)

    if report.get('response_code') == 1:
        html_report = '<html><body>' + json2html.convert(json=report) + '</body></html>'
        write_to_html(html_report, 'Printreport.html')
        report_to_store = {'scanId': scan_id, 'Report': html_report, 'CreatedAt': datetime.utcnow()}
        stored_results_collection.insert_one(report_to_store)
        webbrowser.open('Printreport.html')
        return
    else:
        print('Your resource is queued for analysis. Please try again later after a few minutes.')

def virus_total_larger_size(target_file, target_email, api_key):
    """
    For a case of a larger file size
    If results are found in the database, they are displayed on the browser or else the report is retrieved, stored in the DB, and displayed on the web.

    Parameters:
    -target_email: email where results need to be sent
    -target_file: file that will be scanned
    -api_key: to access the virus total website

    Output:
    -Sends the report to the target email
    """
    scan_id = virus_total_scan(target_file)
    stored_result_retrieved = retrieve_stored_result(scan_id)

    if stored_result_retrieved:
        print('Your scan results are present in the database.')
        result = stored_result_retrieved['Report']
        write_to_html(result, 'result.html')
        webbrowser.open('result.html')
        return

    report = retrieve_report(api_key, scan_id)

    if report.get('response_code') == 1:
        html_report = '<html><body>' + json2html.convert(json=report) + '</body></html>'
        write_to_html(html_report, 'Printreport.html')
        report_to_store = {'scanId': scan_id, 'Report': html_report, 'CreatedAt': datetime.utcnow()}
        stored_results_collection.insert_one(report_to_store)

        # Sending email with results
        send_email(target_email, 'printReport.html')
        print('Check your email in a few minutes.')
        return
    else:
        print('Your resource is queued for analysis. Please try again later after a few minutes.')

def write_to_html(content, file_name):
    """
    Writes HTML content to a file.

    Parameters:
    - content (str): HTML content to be written.
    - file_name (str): File path where the HTML content will be saved.

    Returns:
    None
    """

    with open(file_name, 'w', encoding='utf-8') as file:
        file.write(content)

def send_email(target_email, html_file):
    """
    Sends an email with an HTML file attachment containing VirusTotal query results.

    Parameters:
    - target_email (str): email where results need to be sent
    - html_file (str): file to be sent as body

    Environment Variables:
    - USER_EMAIL: Sender's email address.
    - USER_PASSWORD: Sender's email account password.

    Raises:
    - smtplib.SMTPException: If an error occurs during the email sending process.
    """

    from_email = os.getenv('USER_EMAIL')
    password = os.getenv('USER_PASSWORD')

    message = MIMEMultipart()
    message['From'] = from_email
    message['To'] = target_email
    message['Subject'] = 'Query Results from VirusTotal'

    with open(html_file, 'r', encoding='utf-8') as html:
        body = MIMEText(html.read(), 'html')

    message.attach(body)

    with smtplib.SMTP('smtp.gmail.com', 587) as mailserver:
        mailserver.starttls()
        mailserver.login(from_email, password)
        mailserver.sendmail(from_email, target_email, message.as_string())
        print('Email sent successfully.')

# Driver code
def main():
    file = 'my_file.txt'
    specified_file_size = 1000000
    api_key = input('Enter your API KEY: ')
    try:
        # check if the file exists and is not empty
        if os.path.isfile(file) and os.path.getsize(file) > 0:
            if os.path.getsize('my_file.txt') > specified_file_size:
                print('It may take time to analyze your query as your file size is large; your results will be sent to your email.')
                target_email = input('Please enter your Email Address: ')
                virus_total_larger_size(file, target_email, api_key)
            else:
                virus_total(file, api_key)
        else:
            print('The file is either empty or not present')
    
    except Exception as e:
        print(f'An error occurred: {e}')

if __name__ == '__main__':
    main()
