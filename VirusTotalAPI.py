# Importing necessary libraries
import os
import requests
from datetime import datetime
from json2html import json2html
from flask import Flask
import webbrowser
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv

# Create the MongoDB client and database 
username = os.getenv("MONGODB_USERNAME")
password = os.getenv("MONGODB_PASSWORD")
cluster = os.getenv("MONGODB_CLUSTER")
database_name = os.getenv("MONGODB_DATABASE")

connected_string = f"mongodb+srv://{username}:{password}@{cluster}/{database_name}?retryWrites=true&w=majority"
client = MongoClient(connected_string)
virustotal_db = client.VirustotalFinal
stored_results_collection = virustotal_db.storedresults

# Function to scan and deliver results
def devops_project(target_file):
    api_key = input("Enter your API KEY: ")
    virus_total_scan_api = "https://www.virustotal.com/vtapi/v2/file/scan"
    params_scan = {"apikey": api_key}

    with open(target_file, "rb") as input_file:
        response_scan = requests.post(virus_total_scan_api, files={"file": input_file}, params=params_scan)
        scan_analysis = response_scan.json()

    scan_id = scan_analysis.get("scan_id")

    stored_results_collection.create_index("CreatedAt", expireAfterSeconds=86400)

    stored_result = stored_results_collection.find_one({"scanId": scan_id}, {"Report": 1})

    if stored_result:
        result = stored_result["Report"]
        write_to_html(result, "result.html")
        return webbrowser.open("result.html")

    virus_total_report_api = "https://www.virustotal.com/vtapi/v2/file/report"
    params_report = {"apikey": api_key, "resource": scan_id}
    response_report = requests.get(virus_total_report_api, params=params_report)
    report = response_report.json()

    if report.get("response_code") == 1:
        html_report = "<html><body>" + json2html.convert(json=report) + "</body></html>"
        write_to_html(html_report, "Printreport.html")
        report_to_store = {"scanId": scan_id, "Report": html_report, "CreatedAt": datetime.utcnow()}
        stored_results_collection.insert_one(report_to_store)
        return webbrowser.open("Printreport.html")
    else:
        print("Your resource is queued for analysis. Please try again later after a few minutes.")

# Function to scan and deliver results for larger files
def devops_project_larger(target_file, target_email):
    api_key = input("Enter your API KEY: ")
    virus_total_scan_api = "https://www.virustotal.com/vtapi/v2/file/scan"
    params_scan = {"apikey": api_key}

    with open(target_file, "rb") as input_file:
        response_scan = requests.post(virus_total_scan_api, files={"file": input_file}, params=params_scan)
        scan_analysis = response_scan.json()

    scan_id = scan_analysis.get("scan_id")

    stored_results_collection.create_index("CreatedAt", expireAfterSeconds=86400)

    stored_result = stored_results_collection.find_one({"scanId": scan_id}, {"Report": 1})

    if stored_result:
        print("Your scan results are present in the database.")
        result = stored_result["Report"]
        write_to_html(result, "result.html")
        return webbrowser.open("result.html")

    virus_total_report_api = "https://www.virustotal.com/vtapi/v2/file/report"
    params_report = {"apikey": api_key, "resource": scan_id}
    response_report = requests.get(virus_total_report_api, params=params_report)
    report = response_report.json()

    if report.get("response_code") == 1:
        html_report = "<html><body>" + json2html.convert(json=report) + "</body></html>"
        write_to_html(html_report, "Printreport.html")
        report_to_store = {"scanId": scan_id, "Report": html_report, "CreatedAt": datetime.utcnow()}
        stored_results_collection.insert_one(report_to_store)

        # Sending email with results
        send_email(target_email, "Printreport.html")
        return print("Check your email in a few minutes.")
    else:
        print("Your resource is queued for analysis. Please try again later after a few minutes.")

# Function to write HTML content to a file
def write_to_html(content, file_name):
    with open(file_name, "w") as file:
        file.write(content)

def send_email(target_email, html_file):
    """
    Sends an email with an HTML file attachment containing VirusTotal query results.

    Parameters:
    - recipient_email (str): The recipient's email address.
    - html_file_path (str): The file path to the HTML file with query results.

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

    with open(html_file, "r") as html:
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
    try:
        # check if file exists and is not empty
        if os.path.isfile(file) and os.path.getsize(file) > 0:
            if os.path.getsize("my_file.txt") > specifiedFileSize:
                print("It may take time to analyze your query; your results will be sent to your email.")
                target_email = input("Please enter your Email Address: ")
                devops_project_larger("file", target_email)
            else:
                devops_project("my_file.txt")
        else:
            print("The file is either empty or not present")
    
    except Exception as e:
        print (f"An error occurred: {e}")

