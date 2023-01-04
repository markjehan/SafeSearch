import urllib.request
import bs4 as bs


vendor = input('Enter Vendor Name:').lower()
urlenc = urllib.parse.quote(vendor)
url = "https://cirt.net/passwords?vendor=" + urlenc
request = urllib.request.Request(url)
response = urllib.request.urlopen(request)
    #response = urllib.quote(request)
    #print (response.read().decode('utf-8')) 
    #print (response.read().decode('utf-8'))
soup = bs.BeautifulSoup(response, "html.parser")
    #print(soup.find_all('a'))

for links in soup.find_all('table'):
    abc = links.text
    print (abc)

