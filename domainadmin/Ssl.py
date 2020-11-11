
class Ssl():
    def check(domain):
        data = {}
        print ("Check domain: " + domain)
        import urllib, json
        import urllib.request
        apiurl = "http://api:4006/api/v1/domainadmin/sslexpire/" + domain
        response = urllib.request.urlopen(apiurl)
        data = json.loads(response.read())
        return data

    def expirelist():
        data = {}
        import urllib, json
        import urllib.request
        apiurl = "http://api:4006/api/v1/domainadmin/sslexpire/list"
        response = urllib.request.urlopen(apiurl)
        data = json.loads(response.read())
        return data
