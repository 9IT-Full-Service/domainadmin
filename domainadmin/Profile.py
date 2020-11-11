
class Profile():
    def getProfileExtras(userid):
        data = {}
        import urllib, json
        import urllib.request
        # userid = current_user.id
        apiurl = "http://api:4006/api/v1/domainadmin/profile/extras/" + str(userid)
        response = urllib.request.urlopen(apiurl)
        data = json.loads(response.read())
        return data

    def getProfileId(email):
        data = {}
        import urllib, json
        import urllib.request
        apiurl = "http://api:4006/api/v1/domainadmin/profile/id/" + email
        response = urllib.request.urlopen(apiurl)
        data = json.loads(response.read())
        return data

    def profileFieldUpdate(id,key,value):
        data = {}
        import urllib, json
        import urllib.request
        apiurl = "http://api:4006/api/v1/domainadmin/profile/setfield/" + id + "/" + key + "/" + value
        response = urllib.request.urlopen(apiurl)
        data = json.loads(response.read())
        return data
