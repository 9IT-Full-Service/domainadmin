import urllib, json
import urllib.request

class Api():
    def readApi(apiurl):
        data = {}
        response = urllib.request.urlopen(apiurl)
        return json.loads(response.read())

# try:
#     from urllib.request import Request, urlopen  # Python 3
# except ImportError:
#     from urllib2 import Request, urlopen  # Python 2

# class Api():
#     def readApi(apiurl):
#         data = {}
#         req = urllib.request(apiurl)
#         req.add_header('Authorization', 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MDU5ODAwNjAsIm5iZiI6MTYwNTk4MDA2MCwianRpIjoiMDRhZWIwMzgtZmZkZS00MjliLWJjYTktMjIwMzRiNmFjZWMxIiwiZXhwIjoxNjA1OTg3MjYwLCJpZGVudGl0eSI6ImFkbWluIiwiZnJlc2giOmZhbHNlLCJ0eXBlIjoiYWNjZXNzIn0.zAubkWXOW85cl5z9utCS56b8EyufGu7SC7vryeVJnrs')
#         content = urlopen(req).read()
#         return json.loads(content)
