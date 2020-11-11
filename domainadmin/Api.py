import urllib, json
import urllib.request

class Api():
    def readApi(apiurl):
        data = {}
        response = urllib.request.urlopen(apiurl)
        return json.loads(response.read())
