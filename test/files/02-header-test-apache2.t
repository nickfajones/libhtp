>>>
GET / HTTP/1.0
 Invalid-Folding: 1
Valid-Folding: 2
 2
Normal-Header: 3
Invalid Header Name: 4
Same-Name-Headers: 5
Same-Name-Headers: 6
Empty-Value-Header:
: 8
Header-With-LWS-After: 9
:
Header-With-NUL: BEFORE AFTER


<<<
HTTP/1.0 200 OK
Date: Mon, 31 Aug 2009 20:25:50 GMT
Server: Apache
Connection: close
Content-Type: text/html
Content-Length: 12

Hello World!