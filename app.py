from flask import Flask, render_template, request, url_for,redirect
import requests
import subprocess as sp 
import random
import urllib.request
import bs4 as bs
#these are all libraries which we have imported. FLASK is a library from the library flask we have imported the flask which is a web server 

app = Flask(__name__) #we need to create an app and the app should be a flask app and it should contain the name __name__


@app.route("/") #fpr the app have a route and the route should be / (/ this is the main page aka the index)
def ini():#function define a function with the function name ini ():
    return render_template("index.html") # return - render - give an output template - through a template ("what is the name of the template we want to output")

#print - which gives an output in the console itself, return - return an output to the function 

#in python flask we have mainly 2 types folders which are mandatory to be created static (images,css,php,js) templates (all the html files)

@app.route("/form",methods=["GET","POST"]) #for the app have route the route this time is /form
def ipscanning():

    if request.method == 'POST': # HEY SERVER LISTEN IF AN REQUEST COMES TO THE FUNCTION ipscanning check if it is a post request then go inside a if loop 
        ip_address=request.form['ip'] # whatever you receive (somehow what u received is a string) the name of the string is ip if you find the name of the string to be ip
        #then please assign that string that you received to ip_address variable 

        headers = {
        "accept": "application/json", #i will take your output in the form that you send it to me 
        "x-apikey": "d0f2258cb348dd4d47b59f40e191e8003dbba66f15c1778eec0ec9462aa7558d" #hey this is me you can verify me using this link 
        }
    
        response = requests.get( "https://www.virustotal.com/api/v3/ip_addresses/%s" %ip_address, headers=headers) #get me a response from the request sent using the defined ip address the headers and the link given 
        #SIMPLY GIVEN TO US THIS IS GIVEN ALREADY GIVEN FROM THE VIRUS TOTAL WEB SITE (saying how to send them the request)

        outfromreq = response.json()["data"]["attributes"]["last_analysis_results"] #now the response we receivef please do give it to a variable which outfromreq
        #what you give is json therefore after accepting json now the varaible says in this json you gave i only neeed 
        #data attributes and last analysis results inside date is attributes inside attributes is last analysis results and inside that is whatever we need.

        #print(outfromreq)


        totalenginecount = 0
        totalenginesdetectedcount = 0
        resultengines = []
        enginenames = []

            
        for i in outfromreq: #we have a enginecount which is i which we got outffromreq
            totalenginecount = totalenginecount + 1#counter
            if outfromreq[i]["category"] == "malicious" or outfromreq[i]["category"] == 'suspicious':
                resultengines.append(outfromreq[i]["result"]) #add one to result engine 
                enginenames.append(outfromreq[i]["engine_name"])# addon to engine names as well 
                totalenginesdetectedcount = totalenginesdetectedcount + 1
        
        
            
        if totalenginesdetectedcount > 0:
            #return("The " + str(ip_address) + " is rated as unsafe on " + str(totalenginesdetectedcount) + " engines out of " + str(totalenginecount) + " engines.") 
            return render_template('threatip.html', result=totalenginecount, result2=ip_address, result3=totalenginesdetectedcount)
            #go to the template threatip.html 
            # once the threatip.html is loaded pls make sure to send the following outputs to the html page and it will be called in another way 
        elif totalenginesdetectedcount > -1:
            #return("The " + str(ip_address) + " is rated as Safe on " + str(totalenginecount) + " engines.")


            return render_template('nonthreatip.html', result=totalenginecount, result2=ip_address)


        #print(request.form.get("firstname"))


    return render_template("form.html") # asap the /form is being entered searched display should be this template form.html


#Same thing as IP
@app.route("/hash",methods=["GET","POST"])
def xyz():
    if request.method == 'POST':
        hash=request.form['hash']


        headers = {
            'apikey': "e4a75ced8cd1082843243107f33d9c83"
        }

        response = requests.get( "https://api.metadefender.com/v4/hash/%s" %hash, headers=headers)
        rr = response.json()["scan_results"]["scan_details"]

        c = 0
        countofeng=0

        for i in rr:
            c = c +1 #engine count
            if(rr[i]["threat_found"]) != "":
                countofeng=countofeng+1
                #print(countofeng)

        if countofeng > 0:
            return render_template("threathash.html", result=hash, result2=countofeng, result3=c)

        elif countofeng > -1:
            return render_template("nonthreathash.html",  result=hash, result3=c)
    
    return render_template("hashsearch.html")

@app.route("/pwgen",methods=["GET","POST"])
def pw():
    if request.method == 'POST': #if the button clicked and if the received request is a post request then 

        lower_case = "abcdefghijklmnopqrstuvwxyz" #define lower case letters to lower_case
        upper_case = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" #define upper case letters to upper_case
        number = "0123456789" #define numbers from 0 to 9 to number
        symbol = "!@#$%^&*()_+{}:|\~`/?><,." # define symbols 

        ans = lower_case + upper_case + number + symbol

        length = 18

        password = "".join(random.sample(ans,length)) #password should be joint together at random and the length of the pw should = to 18

        return render_template("pwoutput.html", result=password) #send the output to pwoutput.html with the result of password
    
    return render_template('pwgen.html')


#same thing as IP
@app.route("/domain",methods=["GET","POST"])
def domain():

    if request.method == 'POST':
        domain=request.form['domain']
        headers = {
            "accept": "application/json",
            "x-apikey": "d0f2258cb348dd4d47b59f40e191e8003dbba66f15c1778eec0ec9462aa7558d"
        
        }
        response = requests.get("https://www.virustotal.com/api/v3/domains/%s" %domain, headers=headers)
        outfromreq = response.json()["data"]["attributes"]["last_analysis_results"]

        #print(outfromreq)


        totalenginecount = 0
        totalenginesdetectedcount = 0
        resultengines = []
        enginenames = []

            
        for i in outfromreq:
            totalenginecount = totalenginecount + 1
            if outfromreq[i]["category"] == "malicious" or outfromreq[i]["category"] == 'suspicious':
                resultengines.append(outfromreq[i]["result"])
                enginenames.append(outfromreq[i]["engine_name"])
                totalenginesdetectedcount = totalenginesdetectedcount + 1
        
        
            
        if totalenginesdetectedcount > 0:
            #return("The " + str(ip_address) + " is rated as unsafe on " + str(totalenginesdetectedcount) + " engines out of " + str(totalenginecount) + " engines.") 
            return render_template('threatdomain.html', result=totalenginecount, result2=domain, result3=totalenginesdetectedcount)
        elif totalenginesdetectedcount > -1:
            #return("The " + str(ip_address) + " is rated as Safe on " + str(totalenginecount) + " engines.")


            return render_template('nonthreatdomain.html', result=totalenginecount, result2=domain)


        #print(request.form.get("firstname"))


    return render_template("domain.html")

@app.route("/adv",methods=["GET","POST"]) #the app route is adv and im allowing the server to receive both get and post requests
def premium(): #function premium
    if request.method == 'POST':
        vendor=request.form['vendor']
        #if a post request is received then give the value received to the variable vendor
        
        thevendor = urllib.parse.quote(vendor)#through the url library now we are assigning the vendor to urlenc
        url = "https://cirt.net/passwords?vendor=" + thevendor #combine the vendor to the link 
        req = urllib.request.Request(url) #send the request 
        response = urllib.request.urlopen(req)#once the request is sent a response will be coming capture it 
            #response = urllib.quote(request)
            #print (response.read().decode('utf-8')) 
            #print (response.read().decode('utf-8'))
        soup = bs.BeautifulSoup(response, "html.parser")# make the response readable or nice 
            #print(soup.find_all('a'))

        for links in soup.find_all('table'): #put everything captured in a table format the table format function is below do as it says 
            abc = (formatTable(links)) #assign the values received to abc 
            return render_template('defaultpwoutput.html', result=abc, result2=vendor) #render template defaultpwoutput 

    return render_template('defaultpw.html') #main initial page to be shown 

#put a new function the formatTable
#whatever the text we get please make sure to put it in a table format using tr td 
def formatTable(table):
        text = ''
        rows = table.find_all('tr')
        text += '%s\n' % rows[0].text

        for row in rows[1:]:
            data = row.find_all('td')
            text += '%s: %s\n' % (data[0].text, data[1].text)

        return text #putput return it 
    



app.debug =True

app.run()