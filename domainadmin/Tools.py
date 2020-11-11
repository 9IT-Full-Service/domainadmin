
class Tools():
    def sendVerifyMail(id,verifyhash,mail):
        data = {}
        userid = current_user.id
        apiurl = "http://api:4006/api/v1/domainadmin/profile/sendverify/" + id + "/" + mail + "/" + verifyhash
        response = urllib.request.urlopen(apiurl)
        data = json.loads(response.read())
        return data
