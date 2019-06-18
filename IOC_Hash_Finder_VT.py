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

work_Dir = os.getcwd()

#Get input file path from user
while ('true'):
    user_Input = input(
        "Please choose the input file path\n 1: C:\VT_IOC_Hash_Matcher\Input.csv (Preferred for windows) \n 2: I will type in the full path \n")
    if user_Input == '1':
        input_File_Path = r"C:\VT_IOC_Hash_Matcher\Input.csv"
        while not os.path.isfile(input_File_Path):
            print("The input file path", input_File_Path, "does not exist. Please try again\n")
            user_Input = input(
                "Please choose the input file path\n 1: C:\VT_IOC_Hash_Matcher\Input.csv (Preferred for windows) \n 2: I will type in the full path \n")
            input_File_Path = r"C:\VT_IOC_Hash_Matcher\Input.csv"
        break
    elif user_Input == '2':
        input_File_Path_From_User = input("Please type in the full path for the input file:\n")
        while not os.path.isfile(input_File_Path_From_User):
            print("The entered file path does not exist. Please try again")
            input_File_Path_From_User = input("Please type in the input file path:\n")
        input_File_Path = input_File_Path_From_User
        break
    else:
        print("Invalid option. Try again:")
        continue

#Get API Key file path from user
while ('true'):
    user_Input = input(r"Please choose the API Key file path\n 1: C:\VT_IOC_Hash_Matcher\api_Key.json (Preferred for windows) \n 2: I will type in the full path \n")
    if user_Input == '1':
        API_Key_File_Path = r"C:\VT_IOC_Hash_Matcher\api_Key.json"
        while not os.path.isfile(API_Key_File_Path):
            print("File path:", API_Key_File_Path, "does not exist. Please try again")
            API_Key_Path_From_User = input("Please type in the API Key path:\n")
        API_Key_File_Path = API_Key_Path_From_User
        break
    elif user_Input == '2':
        API_Key_Path_From_User = input("Please type in the full path for the API Key file:\n")
        while not os.path.isfile(API_Key_Path_From_User):
            print("The entered file path does not exist. Please try again")
            API_Key_Path_From_User = input("Please type in the API Key path:\n")
        API_Key_File_Path = API_Key_Path_From_User
        break
    else:
        print("Invalid option. Try again:")
        continue

#Read API Key from file:
#api_Key_File_Path = workDir + r"\api_Key.json"
print("Opening", API_Key_File_Path)
with open(API_Key_File_Path,'r')as API_File:
    API_Data = json.load(API_File)
print(API_Data["api_Key"])
api_Key = API_Data["api_Key"]
if (len(api_Key)) != 64:
    print("Invalid API Key. Run again with valid credentials stored in the API_Key file!!")
    exit(-1)
url = 'https://www.virustotal.com/vtapi/v2/file/report'
print("Working Dir:", work_Dir)
Output_CSV = work_Dir + "\Output.csv"
print("Input File:", input_File_Path)
print("Output File:", Output_CSV)
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
    print("The output file is stored at:",Output_CSV )
exit(0)