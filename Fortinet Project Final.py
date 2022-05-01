# -*- coding: utf-8 -*-
"""
Created on Sun May  1 00:40:06 2022

@author: cheru
"""

import requests             #needed to access eg. the API post and get 
from json2html import *     #to convert json output to html
from flask import Flask     # needed for making a web app script
import webbrowser           # to open html files in python script
from datetime import *      # to use date time features
import os                   # used to get the file size in below code
import smtplib              #to access the SMTP server for sending emails
from email.mime.multipart import MIMEMultipart    #to attach seperate messages to email(different contents)
from email.mime.text import MIMEText              #to echange text over email
from email.mime.base import MIMEBase   
from email import encoders  #encoding needed for MTAs(Mssg transfer agent) to properly process the
from pymongo import MongoClient                   # to create and access the mongo database
from pprint import pprint   #To print Data Structures in a readable way

#Create the database and its collection

client=MongoClient('mongodb+srv://cherub_randhawa:csrS*1897@cluster0.ujhb8.mongodb.net/virustotal?retryWrites=true&w=majority')

db=client.VirustotalFinal

storedresults=db.storedresults

#Defining a function to Scan and Deliver the results of file attached

def Devopsproject(targetfile):

    ApiKey=input("Enter your API KEY ")

    VirusTotalScan_API= "https://www.virustotal.com/vtapi/v2/file/scan" #To connect to VirusTotal

    ParamsScan={"apikey":ApiKey}                                        #Get the API KEY for authentication

    InputFile={"file": open(targetfile,"rb")}                           #Opening in the file in binary read format

    ResponseScan=requests.post(VirusTotalScan_API,files=InputFile, params=ParamsScan)

    ScanAnalysis=ResponseScan.json()                                    #Converting the reposnse into json file

    ScanId=ScanAnalysis['scan_id']                                      #Retreiving Scanid for futrther use
    
    storedresults.create_index("CreatedAt", expireAfterSeconds=86400)   #To clear the database after every 24 hours i.e86400 seconds
    
    cursor=storedresults.find({},{'scanId':ScanId,'Report':1})          #Finding the cursor of desired ScanId
    
    store={}
    
    #If ScanId exists in database it would be retreived from it and a webpage would be opened
    
    if cursor is not None:

        for i in cursor:
            
            store=i
        
        if  store and store['scanId']==ScanId:  #if store is not empty and scna id is present in it
        
            result=store['Report']
            
            f=open('result.html','w')     

            f.write(result)

            f.close()

            return webbrowser.open('result.html') 
    
    #To retreive take the scan to website and retrive results from there in case nothing is there in Database

    VirusTotalReport_API="https://www.virustotal.com/vtapi/v2/file/report"

    ParamsReport={"apikey":ApiKey,

                  "resource":ScanAnalysis['scan_id']}     #to retreive reports using api key and resorce whiche here is scanid

    ResponseReport=requests.get(VirusTotalReport_API,params=ParamsReport)

    Report=ResponseReport.json()                          #Converting report to json file

    if Report['response_code']==1:

        HTMLReport="<html>" + "<body>" + json2html.convert(json = Report)+ "</body>" + "</html>"    #Converting json file to HTML and adding html tag to it
        
        Printreport=open('Printreport.html','w')          #Open report and write html file on it

        Printreport.write(HTMLReport)

        Printreport.close()

        Report2bStored={'scanId':ScanId,'Report':HTMLReport,'CreatedAt':datetime.utcnow()}          #Store data in database with following keys and a time tage for TTL

        storedresults.insert_one(Report2bStored)         #Add report to database collection

        return webbrowser.open('Printreport.html')       #Open the html file 

    else:

        print("Your resource is queued for analysis please try again later after few minutes")

#If the file size is large send it to mail and store and retreive from database same as above
            
def DevopsProjectLarger(targetfile,TargetEmail):

    ApiKey=input("Enter your API KEY ")

    VirusTotalScan_API= "https://www.virustotal.com/vtapi/v2/file/scan"
    
    ParamsScan={"apikey":ApiKey}
    
    InputFile={"file": open(targetfile,"rb")}
    
    ResponseScan=requests.post(VirusTotalScan_API,files=InputFile, params=ParamsScan)
    
    ScanAnalysis=ResponseScan.json()
    
    ScanId=ScanAnalysis['scan_id']
    
    storedresults.create_index("CreatedAt", expireAfterSeconds=86400)
    
    cursor=storedresults.find({},{'scanId':ScanId,'Report':1})
    
    store={}
    
    if cursor is not None:

        for i in cursor:
            
            store=i
        
        if  store and store['scanId']==ScanId:
            
            print("Your scan results are present in database")
        
            result=store['Report']
            
            f=open('result.html','w')

            f.write(result)

            f.close()

            return webbrowser.open('result.html')
    
    VirusTotalReport_API="https://www.virustotal.com/vtapi/v2/file/report"
    
    ParamsReport={"apikey":ApiKey,
                  "resource":ScanAnalysis['scan_id']}
    
    ResponseReport=requests.get(VirusTotalReport_API,params=ParamsReport)
    
    Report=ResponseReport.json()
    
    if Report['response_code']==1:

        HTMLReport="<html>" + "<body>" + json2html.convert(json = Report)+ "</body>" + "</html>"
        
        Printreport=open('printreport.html','w')

        Printreport.write(HTMLReport)
        
        Printreport.close()
        
        Report2bStored={'scanId':ScanId,'Report':HTMLReport,'CreatedAt':datetime.utcnow()}

        storedresults.insert_one(Report2bStored)
        
        #Below snippet is used to access SMTP server and send results over email    
        html=open("Printreport.html")
        msg=MIMEText(html.read(),'html')     #Read HTML file and store it in msg
        msg['From']='cherubs@gmail.com'
        msg['To']=TargetEmail
        msg['Subject']='Query Results form VirusTotal'
        mailserver=smtplib.SMTP('smtp.gmail.com',587)     #Accesing gmail server
        mailserver.starttls()
        mailserver.login("cherub.project80@gmail.com","cherub1897")
        text=msg.as_string()                              #Convert msg as string
        mailserver.sendmail('cherub.prpject80@gmail.com',TargetEmail,text)   #Send that HTML file over email
        mailserver.quit()
        print("Check your email in few minutes")
    
    else:

        print("Your resource is queued for analysis please try again later after few minutes")
    
    
#####DRIVER CODE BELOW#####    
            
        
        
if os.path.getsize('my_file.txt')> 1000000:                   #if file size is greater than 1mb
        print("It may take time to analyze your query, no need to wait your results will be sent on your email")
        
        TargetEmail=input(" Please Enter your Email Address ")
        
        DevopsProjectLarger('my_file.txt',TargetEmail)
        
else:
    
    Devopsproject('my_file.txt')

