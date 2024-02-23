# Importing necessary libraries
import os
import requests
from datetime import datetime
from json2html import json2html
import webbrowser
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

# Create the MongoDB client and database 
username = os.getenv("MONGODB_USERNAME")
password = os.getenv("MONGODB_PASSWORD")
cluster = os.getenv("MONGODB_CLUSTER")
database_name = os.getenv("MONGODB_DATABASE")

connected_string = f"mongodb+srv://{username}:{password}@{cluster}/{database_name}?retryWrites=true&w=majority"
client = MongoClient(connected_string)
virustotal_db = client.VirustotalFinal
stored_results_collection = virustotal_db.storedresults

def virusTotalScan(target_file, api_key):
    """
    Posts the file to Virus Total for Scanning using Virus Total API

    Parameters:
    - target file -> file to be scanned
    - api key -> api key to access virus total website

    Output:
    - returns the scan id so that we can check if this scan has happened before and if it is present in database
    """

    virus_total_scan_api = "https://www.virustotal.com/vtapi/v2/file/scan"
    params_scan = {"apikey": api_key}

    with open(target_file, "rb") as input_file:
        response_scan = requests.post(virus_total_scan_api, files={"file": input_file}, params=params_scan)
        scan_analysis = response_scan.json()

    scanId = scan_analysis.get("scan_id")
    return scanId

def retrieveStoredResult(scan_id):
    """
    This method retrieves stored results from mongo db collection 
    also creates an index with TTL of 24 hours

    Parameters:
    -scan id -> to look for reports in database

    Output:
    - returns report according to scan id 
    """

    stored_results_collection.create_index("CreatedAt", expireAfterSeconds=86400)
    return stored_results_collection.find_one({"scanId": scan_id}, {"Report": 1})

def retrieveReport(scan_id, api_key):
    """
    This method retrieves results from Virus total 

    Parameters:
    - scan id
    - api key

    output:
    -Generates a report in from of JSON
    """

    virus_total_report_api = "https://www.virustotal.com/vtapi/v2/file/report"
    params_report = {"apikey": api_key, "resource": scan_id}
    response_report = requests.get(virus_total_report_api, params=params_report)
    return response_report.json()


def virusTotal(target_file, api_key):
    """
    If results are found in database they are displayed on browser or else report is retrieved, stored in DB and displayed on web.

    Parameters:
    -target file
    -api key

    output:
    -Displays a report in form of html table on web
    """
    scan_id = virusTotalScan(target_file)
    stored_result_retrieved = retrieveStoredResult(scan_id)

    if stored_result_retrieved:
        print("Your scan results are already present in the database")
        finalResult = stored_result_retrieved["Report"]
        write_to_html(finalResult, "result.html")
        return webbrowser.open("result.html")

    report = retrieveReport(api_key, scan_id)

    if report.get("response_code") == 1:
        html_report = "<html><body>" + json2html.convert(json=report) + "</body></html>"
        write_to_html(html_report, "Printreport.html")
        report_to_store = {"scanId": scan_id, "Report": html_report, "CreatedAt": datetime.utcnow()}
        stored_results_collection.insert_one(report_to_store)
        return webbrowser.open("Printreport.html")
    else:
        print("Your resource is queued for analysis. Please try again later after a few minutes.")

def virusTotalLargerSize(target_file, target_email, api_key):
    """
    For a case of larger file size
    If results are found in database they are displayed on browser or else report is retrieved, stored in DB and displayed on web.

    Parameters:
    -target email
    -target file
    -api key

    output:
    -Sends the report to the target email

    """
    scan_id = virusTotalScan(target_file)
    stored_result_retrieved = retrieveStoredResult(scan_id)

    if stored_result_retrieved:
        print("Your scan results are present in the database.")
        result = stored_result_retrieved["Report"]
        write_to_html(result, "result.html")
        return webbrowser.open("result.html")

    report = retrieveReport(api_key, scan_id)

    if report.get("response_code") == 1:
        html_report = "<html><body>" + json2html.convert(json=report) + "</body></html>"
        write_to_html(html_report, "Printreport.html")
        report_to_store = {"scanId": scan_id, "Report": html_report, "CreatedAt": datetime.utcnow()}
        stored_results_collection.insert_one(report_to_store)

        # Sending email with results
        send_email(target_email, "printReport.html")
        return print("Check your email in a few minutes.")
    else:
        print("Your resource is queued for analysis. Please try again later after a few minutes.")

def write_to_html(content, file_name):
    """
    Writes HTML content to a file.

    Parameters:
    - content (str): HTML content to be written.
    - file_name (str): File path where the HTML content will be saved.

    Returns:
    None
    """

    with open(file_name, "w", encoding="utf-8") as file:
        file.write(content)

def send_email(target_email, html_file):
    """
    Sends an email with an HTML file attachment containing VirusTotal query results.

    Parameters:
    - recipient_email (str)
    - html_file_path (str)

    Environment Variables:
    - USER_EMAIL: Sender's email address.
    - USER_PASSWORD: Sender's email account password.

    Raises:
    - smtplib.SMTPException: If an error occurs during the email sending process.

    """

    from_email = os.getenv("USER_EMAIL")
    password = os.getenv("USER_PASSWORD")

    message = MIMEMultipart()
    message["From"] = from_email
    message["To"] = target_email
    message["Subject"] = 'Query Results from VirusTotal'

    with open(html_file, "r", encoding="utf-8") as html:
        body = MIMEText(html.read(), "html")

    message.attach(body)

    with smtplib.SMTP("smtp.gmail.com", 587) as mailserver:
        mailserver.starttls()
        mailserver.login(from_email, password)
        mailserver.sendmail(from_email, target_email, message.as_string())
        print("Email sent successfully.")

# Driver code
def main():
    file = "my_file.txt"
    specifiedFileSize = 1000000
    api_key = input("Enter your API KEY: ")
    try:
        # check if file exists and is not empty
        if os.path.isfile(file) and os.path.getsize(file) > 0:
            if os.path.getsize("my_file.txt") > specifiedFileSize:
                print("It may take time to analyze your query as your file size is large; your results will be sent to your email.")
                target_email = input("Please enter your Email Address: ")
                virusTotalLargerSize(file, target_email, api_key)
            else:
                virusTotal(file, api_key)
        else:
            print("The file is either empty or not present")
    
    except Exception as e:
        print (f"An error occurred: {e}")

