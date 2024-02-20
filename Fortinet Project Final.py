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

# Create the MongoDB client and database
client = MongoClient('mongodb+srv://cherub_randhawa:csrS*1897@cluster0.ujhb8.mongodb.net/virustotal?retryWrites=true&w=majority')
db = client.VirustotalFinal
stored_results = db.storedresults

# Function to scan and deliver results
def devops_project(target_file):
    api_key = input("Enter your API KEY: ")
    virus_total_scan_api = "https://www.virustotal.com/vtapi/v2/file/scan"
    params_scan = {"apikey": api_key}

    with open(target_file, "rb") as input_file:
        response_scan = requests.post(virus_total_scan_api, files={"file": input_file}, params=params_scan)
        scan_analysis = response_scan.json()

    scan_id = scan_analysis.get('scan_id')

    stored_results.create_index("CreatedAt", expireAfterSeconds=86400)

    stored_result = stored_results.find_one({"scanId": scan_id}, {'Report': 1})

    if stored_result:
        result = stored_result['Report']
        write_to_html(result, 'result.html')
        return webbrowser.open('result.html')

    virus_total_report_api = "https://www.virustotal.com/vtapi/v2/file/report"
    params_report = {"apikey": api_key, "resource": scan_id}
    response_report = requests.get(virus_total_report_api, params=params_report)
    report = response_report.json()

    if report.get('response_code') == 1:
        html_report = "<html><body>" + json2html.convert(json=report) + "</body></html>"
        write_to_html(html_report, 'Printreport.html')
        report_to_store = {'scanId': scan_id, 'Report': html_report, 'CreatedAt': datetime.utcnow()}
        stored_results.insert_one(report_to_store)
        return webbrowser.open('Printreport.html')
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

    scan_id = scan_analysis.get('scan_id')

    stored_results.create_index("CreatedAt", expireAfterSeconds=86400)

    stored_result = stored_results.find_one({"scanId": scan_id}, {'Report': 1})

    if stored_result:
        print("Your scan results are present in the database.")
        result = stored_result['Report']
        write_to_html(result, 'result.html')
        return webbrowser.open('result.html')

    virus_total_report_api = "https://www.virustotal.com/vtapi/v2/file/report"
    params_report = {"apikey": api_key, "resource": scan_id}
    response_report = requests.get(virus_total_report_api, params=params_report)
    report = response_report.json()

    if report.get('response_code') == 1:
        html_report = "<html><body>" + json2html.convert(json=report) + "</body></html>"
        write_to_html(html_report, 'Printreport.html')
        report_to_store = {'scanId': scan_id, 'Report': html_report, 'CreatedAt': datetime.utcnow()}
        stored_results.insert_one(report_to_store)

        # Sending email with results
        send_email(target_email, 'Printreport.html')
        return print("Check your email in a few minutes.")
    else:
        print("Your resource is queued for analysis. Please try again later after a few minutes.")

# Function to write HTML content to a file
def write_to_html(content, file_name):
    with open(file_name, 'w') as file:
        file.write(content)

# Function to send email with HTML file attachment
def send_email(target_email, html_file):
    from_email = 'cherubs@gmail.com'
    password = 'cherub1897'

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = target_email
    msg['Subject'] = 'Query Results from VirusTotal'

    with open(html_file, 'r') as html:
        body = MIMEText(html.read(), 'html')

    msg.attach(body)

    with smtplib.SMTP('smtp.gmail.com', 587) as mailserver:
        mailserver.starttls()
        mailserver.login(from_email, password)
        mailserver.sendmail(from_email, target_email, msg.as_string())
        print("Email sent successfully.")

# Driver code
if os.path.getsize('my_file.txt') > 1000000:
    print("It may take time to analyze your query. No need to wait; your results will be sent to your email.")
    target_email = input("Please enter your Email Address: ")
    devops_project_larger('my_file.txt', target_email)
else:
    devops_project('my_file.txt')
