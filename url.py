import re
import whois
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import requests
from datetime import date

# Presence of IP address in the given URL is almost a confirmed indication of the website 
# being a suspicious website
# Regex to check if an URL contains an IP
IP_regex = r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
# Phishing URLs are constructed long in order to obfuscate the malicious part
# Number of characters for which the URL is considered long
longURLsValue = 54
# Phishers often add valid sub domain names in the URL to make it appear as a legitimate URL
# The following number is used to extract the feature related to what it is said above
numSubDomains = 3

class URL:
    """
    A class used to represent a URL and its related features.
    It also contains methods necessary for extracting the features.
    Attributes
    ----------
    url : str
        the url of the site
    isPhishingURL : int
        1 if the url is phishing, 0 otherwise
    HTTPSProtocol : int
        if the URL protocol is HTTPS then it is set to 0, otherwise it is set to 1
    containsIpAddress : int
        this feature value is set to 1 if there exists an IP address in the given URL, to 0 otherwise
    isLong : int
        it is set to 1 if the URL is longer than 54 characters, to 0 otherwise
    containsAtSymbol : int
        if a URL contains @ this feature receives the value of 1, 0 otherwise
    containsMinus : int
        this feature is set to 1 when there is a “-” in the domain name, to 0 otherwise
    subDomains : int
        if the number of dots (i.e., “.”) in the hostname is fewer than three this feature is set to zero. Otherwise, it is set to 1
    anchorURLs : int
        this feature is set to 1 if the number of anchor tags <a> whose domain is different from that of the website or does not link to any webpage is greater than 20%
    requestURL : int
        this feature is set to 1 if the number of <src> tags whose domain is different from that of the website is greater than 20%
    DNSRecord : int
        if the URL doesn't have any registered name servers in the WHOIS database then this feature is set to 1, to 0 otherwise
    domainAge : int
        if the URL was registered less than one year ago in the WHOIS database then this feature is set to 1, to 0 otherwise
    unusualURLs : int
        if the URL does not exists in the registered domain names in WHOIS database then this feature is set to 1, to 0 otherwise
    """

    # The following features reported in the reference paper are not used for the sake of simplicity and security:
    #    8-Link Hiding
    #    10-Page Redirects
    #    11-Pop-up Windows
    #    13-Server from Handlers

    def __init__(self, url, isPhishingURL):
        self.url = url

        if(urlparse(self.url).scheme == 'https'):
            self.HTTPSProtocol = 0
        else:
            self.HTTPSProtocol = 1

        self.containsIpAddress = 0 if re.search(IP_regex, self.url) == None else 1
        self.isLong = 0 if len(self.url) < longURLsValue else 1 
        self.containsAtSymbol = 1 if '@' in self.url else 0
        self.containsMinus = 1 if '-' in self.url else 0
        self.subDomains = 1 if self.url.count('.') > numSubDomains else 0
        self.anchorURLs, self.requestURL = self.scrape_HTML(url)
        self.DNSRecord, self.domainAge, self.unusualURLs = self.perform_whois(url)
        self.isPhishingURL = isPhishingURL


    def get_list_feature(self):
        return [self.HTTPSProtocol, self.containsIpAddress, self.isLong, self.containsAtSymbol, 
                self.containsMinus, self.subDomains, self.anchorURLs, self.DNSRecord, self.requestURL,
                self.domainAge, self.unusualURLs]
    

    def get_tuple_representation(self):
        return (self.url, self.isPhishingURL, self.get_list_feature)


    def print_csv(self):
        separator = ', '
        result = str(self.url + separator + self.isPhishingURL + separator)
        for feature in self.get_list_feature():
            result += str(feature)
            result += separator
        # small bug discovered later: also the last feature is followed by a comma
        # I reported here a possible fix:
        #for i in range(0, len(self.get_list_feature()) - 1):
        #    result += str(feature)
        #    result += separator
        #result += self.get_list_feature()[len(self.get_list_feature()) - 1]
        return result

    def scrape_HTML(self, url):
        try:
            page = requests.get(url)
            soup = BeautifulSoup(page.content, 'html.parser')
            anchorURLs = 0
            requestURL = 0

            #Extraction of the feature Anchor URLs
            numOfLinks = 0
            numOfSuspiciuosLinks = 0
            #first of all I find all the <a> tag and then look at the href attribute
            for a in soup.find_all('a', href=True):
                numOfLinks += 1
                if a['href'] == '#' or a['href'] == '#content' or a['href'] == '#skip' or a['href'] == 'JavaScript ::void(O)':
                    numOfSuspiciuosLinks += 1 #the anchor does not link to any webpage
                elif urlparse(a['href']).scheme != urlparse(url).scheme and urlparse(a['href']).netloc != urlparse(url).netloc:
                    #the url in href is from a different domain
                    #then to avoid cases of relative paths inside the same domain I make another check
                    if urlparse(a['href']).scheme != '' and urlparse(a['href']).netloc != '':
                        numOfSuspiciuosLinks += 1 #the anchor links to another domain
            if numOfSuspiciuosLinks * 100 > 20 * numOfLinks:
                        anchorURLs = 1 #the webpage has suspicious anchors more than 20%, then this feature is set to one

            #Extraction of the feature Request URL
            numOfLinksInImages = 0
            numOfSuspiciuosLinksInImages = 0
            for image in soup.find_all('img', src=True):
                numOfLinksInImages += 1
                if urlparse(image['src']).scheme != urlparse(url).scheme and urlparse(image['src']).netloc != urlparse(url).netloc:
                    #the url in href is from a different domain
                    #then to avoid cases of relative paths inside the same domain I make another check
                    if urlparse(image['src']).scheme != '' and urlparse(a['href']).netloc != '':
                        numOfSuspiciuosLinksInImages += 1 #the anchor links to another domain
            if numOfSuspiciuosLinksInImages * 100 > 20 * numOfLinksInImages:
                        requestURL = 1 #the webpage has suspicious src URL more than 20%, then this feature is set to one
        
            return anchorURLs, requestURL
        except Exception:
            return 1, 1 #if it is not possible to connect for scraping then it is probably a phishing url


    def perform_whois(self, url):
        DNSRecord = 0
        domainAge = 0
        unusualURLs = 0
        try:
            result = whois.whois(url)
            if result.name_servers is None: 
                DNSRecord = 1 #no information in whois, probably phishing

            if result.creation_date is not None:
                if result.creation_date[1].year - date.today().year <= 1 or result.creation_date[1].year == '':
                    domainAge = 1 #the website is younger than one year old
            else:
                 domainAge = 1
            
            if result.domain_name is None:
                unusualURLs = 1
        except Exception:
            return DNSRecord, domainAge, unusualURLs #given the dataset is handmade, this should never happens

        return DNSRecord, domainAge, unusualURLs
