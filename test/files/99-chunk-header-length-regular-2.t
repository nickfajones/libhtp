>>>
GET / HTTP/1.0
User-Agent: Mozilla
Transfer-Encoding: chunked

1
1
2
12
3
123
4
1234
5
12345
6
123456
7
1234567
8
12345678
9
123456789
a
123456789a
11
123456789abcdef01
0


<<<
HTTP/1.0 200 OK
Date: Sat, 29 Nov 2014 16:00:00 HKT
Server: Apache
Connection: close
Transfer-Encoding: chunked
Content-Type: text/html

11
123456789abcdef01
a
123456789a
9
123456789
8
12345678
7
1234567
6
123456
5
12345
4
1234
3
123
2
12
1
1
0

