import requests
import json
import time
import csv
import os

# Function to write an array values to CSV row
def writeCSV (row,Output_CSV):
    # Write to output file CSV
    with open(Output_CSV, 'w+', newline='') as csvFile:
        writer = csv.writer(csvFile)
        writer.writerow(row)
    csvFile.close()

#IOC_Hash = "f9992dfb56a9c6c20eb727e6a26b0172"
#Function to Create working directory if it doesn't exist already
#workDir = "C:\VT_IOC_Hash_Matcher"

#Get present working directory
workDir = os.getcwd()
user_Input = input("Please choose the input file path\n 1: C:\VT_IOC_Hash_Matcher\Input.csv (Preferred for windows) \n 2: I will type in the full path \n")
if user_Input == '1':
    input_File_Path = "C:\VT_IOC_Hash_Matcher\Input.csv"
elif user_Input == '2':
    user_Input_Option = input("Please type in the directory:\n")
    input_File_Path = user_Input_Option
else:
    print("Invalid option. Please run again!")
    workDir = "None"
    exit(-1)
#input_File_Path = workDir + "\Input.csv"
api_Key = 'a86c11b36346da6309f284a270b80ace7a38139de3a35920bc53b35bc5aba07d'
url = 'https://www.virustotal.com/vtapi/v2/file/report'
Output_CSV = workDir + "\Output.csv"
print("Output File:", Output_CSV)
print("Working Dir:", workDir)

#Check if file exists:
exists = os.path.isfile(input_File_Path)
if not exists:
    print("Input File: ", input_File_Path, "doesn't exist at", workDir)
    exit(-1)

row_start = ["Input Value", "md5", "sha1", "sha256"]
writeCSV (row_start, Output_CSV)

# Open input file with hash values in read mode
with open(input_File_Path,'r')as i_File:
    data = csv.reader(i_File)
    for row in data:
        IOC_Hash = row[0]
        params = {'apikey': api_Key, 'resource': IOC_Hash}
        # VT API Query:
        response = requests.get(url, params=params)
        HTTP_Status_Code = response.status_code
        if HTTP_Status_Code == 200:
            #This is in 'dict' object format
            response_dict = (response.json())
            response_Code = response_dict['response_code']
            message_From_VT = response_dict['verbose_msg']
            #print("Response Code:", response_Code)
            if response_Code == 0:
                #response_Code means the hash value was not found in VT)
                sha1 = 'Not found'
                sha256 = 'Not found'
                md5 = 'Not found'
                print("Input Value:", IOC_Hash, "sha256:", sha256, "sha1:", sha1, "md5:", md5, "Message from VT", message_From_VT)
                row_Not_Found = [IOC_Hash, md5, sha1, sha256, message_From_VT]
                # Write to CSV output File
                writeCSV(row_Not_Found, Output_CSV)
                continue
            elif response_Code == 1:
                sha256 = response_dict['sha256']
                md5 = response_dict['md5']
                sha1 = response_dict['sha1']
                time.sleep(15)
                print("Input Value:", IOC_Hash, "sha256:", sha256, "sha1:", sha1, "md5:", md5, "Message from VT", message_From_VT )
                row = [IOC_Hash, md5, sha1, sha256, message_From_VT]
                #Write to output file CSV
                writeCSV(row, Output_CSV)
            else:
                print("VT could not return required info for some reason")
        else:
            print ("The HTTP request to VT was not successful")
    #Close the input file
    i_File.close()
    exit(0)