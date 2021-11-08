import json
import csv

#load json file first
f = open('scan.results.json')
data = json.load(f)
#print(data)

result = data["vulnerabilities"]
print(result)

final = {}
mylist = []
            
for i in result:
    cve = {}
    alerts = {}
    
    #list to string
    #alerts["CVE-id"]= i["identifiers"]["CVE"]
    cve = i["identifiers"]["CVE"]
    alerts["CVE-ID"] = ''.join(cve)
    
    #remove new line
    alerts["DESCRIPTION"]= i["description"].replace('\n', '')
    

    alerts["SEVERITY"]= i["nvdSeverity"]
    mylist.append(alerts)
    final["workshop8"] = mylist

with open("sample1.json", "w") as fhandle:
    json.dump(final, fhandle, indent=4)
    
with open('sample1.json') as json_file:
    data1 = json.load(json_file)

em_data = data1['workshop8']
    
data_file = open('sample1.csv', 'w')
csv_writer = csv.writer(data_file)

count = 0
for i in em_data:
    if count == 0:
        header = i.keys()
        csv_writer.writerow(header)
        count +=1
    csv_writer.writerow(i.values())
data_file.close()

    



