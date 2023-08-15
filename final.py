import requests
from bs4 import BeautifulSoup 
import csv
from urllib.parse import urljoin, quote 
import re

def getformdetails(form):
    details={}
    action_attr = form.attrs.get('action', '').lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    details['action'] = action_attr
    details['method']=method
    details["inputs"] = inputs
    return details

def getallforms(url):
    response = requests.get(url)
    soup=BeautifulSoup(response.content,'html.parser')
    return soup.find_all('form')

def testforXSS (url):
    filecontent=""
    forms = getallforms(url)
    instances = []
    with open('XSS_dataset.csv', 'r', encoding = 'utf-8') as dataset:
        reader = csv.DictReader(dataset)
        instances = [row['Sentence'] for row in reader if row['Label'] == '1']
    success_count = 0
    instancetested =0 
    for instance in instances:
        payload = instance
        instancetested+=1
        for form in forms:
            formdetails = getformdetails(form)
            target_url = urljoin(url, formdetails["action"])
            inputs = formdetails["inputs"]
            data = {}
            for input in inputs:
                if input["type"] == "text" or input["type"] == "search":
                    input["value"] = payload
                    input_name = input.get("name")
                    input_value = input.get("value")
                    if input_name and input_value:
                        data[input_name] = input_value
                    target_url += "?"
                    datakeys = list(data.keys())
                    for i in range(len(datakeys)):
                        target_url +=  datakeys[i]
                        target_url += "="
                        target_url+=quote(data[datakeys[i]])
                        if i!= len(datakeys)-1:
                            target_url += "&"      
                    if formdetails["method"] == "post":
                        content = requests.post(target_url, data=data)
                    else:
                        content = requests.get(target_url, data=data)
                    s = BeautifulSoup(content.content, 'html.parser')
                    text_content = s.get_text()
                    if payload not in text_content:
                        filecontent+=f"\nXSS vulnerability detected with the instance : { payload }!\n"
                        success_count += 1
                    if(success_count>=10):
                        filecontent += "\nThe website follows poor input validation!!"
                        filecontent += f"\n{success_count} instances out of {instancetested} were found to be malicious! "
                        return filecontent
    filecontent +="\nThis webpage seems to be less or not vulnerable to XSS :) \n"
    filecontent+=f"\n{success_count} instances out of {instancetested} were found to be malicious! "
    return filecontent

if __name__ == '__main__':
    url = input("Enter the url : ")
    print(testforXSS(url))
