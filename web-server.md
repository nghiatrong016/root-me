# Insecure Code Management
Dùng dirseach thì mình tìm thấy file .git

![alt text](image.png)

![alt text](image-1.png)

Dùng wget -r `<url>` để tải src về

Use git show to check for git commit change
![alt text](image-2.png)

# files install 

![alt text](image-4.png)

![alt text](image-5.png)

![alt text](image-6.png)

![alt text](image-3.png)

# file upload -mime type

![alt text](image-8.png)

![alt text](image-7.png)

# file upload double extenions

Dùng a.php.png

![alt text](image-9.png)

# HTTP - Improper redirect

Truy cập vào thẳng index xem trong Burp sẽ thấy được

Có vẻ như nếu redirect mà không exit thì code ở phía dưới nếu có vẫn sẽ được thực thi

![alt text](image-10.png)

# Nginx - Alias Misconfiguration

**Một chút lý thuyết:**

Directive alias dùng để thay thế đường dẫn của một location nhất định. Ví dụ:

```nginx
location /i/ {
    alias /data/w3/images/;
}
```

- Khi người dùng yêu cầu /i/top.gif, Nginx sẽ trả về file /data/w3/images/top.gif.
- location kết thúc bằng dấu /, nên các yêu cầu bên trong /i/ sẽ chỉ ánh xạ vào /data/w3/images/.

Lỗi xảy ra khi không có dấu /
Nếu cấu hình như sau:

```nginx
location /i {
    alias /data/w3/images/;
}
```
- Khi người dùng yêu cầu /i/top.gif, Nginx load file /data/w3/images/top.gif
- Nếu kẻ tấn công yêu cầu /i../app/config.py, đường dẫn sẽ bị ánh xạ thành:
```nginx
/data/w3/images/../app/config.py → /data/w3/app/config.py
```
Điều này có nghĩa là file config.py nằm ngoài thư mục /data/w3/images/ nhưng vẫn bị lộ.

[Ref Link](https://github.com/yandex/gixy/blob/master/docs/en/plugins/aliastraversal.md)

**Khai thác:** Từ lỗi misconfiguration ở trên ta có thể lợi dụng thể path traversal.

Đầu tiên khi vào link challenge thì không có gì đặc biệt, tuy nhiên khi mình vào Burp để xem request thì thấy 1 file main.js, mà nó còn show code cho mình nữa.

![alt text](image-11.png)

Với kiến thức đã đọc được ở trên thì mình thử tấn công, đầu tiên hiện tại file mình muốn đọc không phải là `main.js` nữa, có thể là một file nào đó khác và với đặc thù của path traversal thì cứ `../` tới chết.

![alt text](image-12.png)

Có vẻ mình đã đúng hướng.

![alt text](image-13.png)

Tới đây thì có hint luôn thêm `/assets` vào.

![alt text](image-14.png)

Tới đây thì thấy cả folder ngoài cùng rồi và cả flag.

![alt text](image-15.png)

# Verb tampering

Bài này thì mình thấy khác là chơi chữ tampering có nghĩa là giả mạo, chỉ cần thay đổi http method trừ get và post là sẽ đọc được flag

![alt text](image-16.png)

# CRLF

![alt text](image-17.png)

# Flask - Unsecure session

Bài này thì mình nhận được một jwt hơi lạ

![alt text](image-18.png)

Bình thường thì một jwt token sẽ gồm

**Header.Payload.Signature**

    Header: Chứa thuật toán
    Payload: Chứa thông tin user
    Signature: Hash của 2 cái trên với key

Tuy nhiên với bài này thì cái payload lại nằm ở đầu, sau đó mình xem được [Video](https://www.youtube.com/watch?v=-ApYZewPLNQ) này, nhưng cũng chưa được giải thích rõ lắm.

**Command:**`flask-unsign --wordlist rockyou.txt --unsign --cookie 'eyJhZG1pbiI6ImZhbHNlIiwidXNlcm5hbWUiOiJndWVzdCJ9.Z7FU8g.3SnSsOXWN4smUAbxs-Ez9oYz4nM' --no-literal-eval`

![alt text](image-19.png)

Sau đó thì thay payload của mình vào rồi tạo token lại thôi

**Command**`flask-unsign --sign --cookie '{"admin": "true", "username" : "admin"}' --secret 's3cr3t'`
![alt text](image-21.png)

![alt text](image-20.png)

# GraphQL instropection
Sau một hồi tìm hiểu về GraphQL thì mình thấy trang [graphql-voyager](https://graphql-kit.com/graphql-voyager/)

Trang này chủ yếu dùng dữ liệu trả về của GraphQL query để vẽ biểu đồ quan hệ

![alt text](image-22.png)

Sau đó thì thấy cái này mình dùng thử thì được query như sau:
```json
{"query":"{__schema{queryType{name},mutationType{name},types{kind,name,description,fields(includeDeprecated:true){name,description,args{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue},type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},isDeprecated,deprecationReason},inputFields{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue},interfaces{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},enumValues(includeDeprecated:true){name,description,isDeprecated,deprecationReason,},possibleTypes{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}}},directives{name,description,locations,args{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue}}}}"}
```

Sau khi dùng query trên thì mình nhận về 1 chuỗi data json dài vcl

![alt text](image-24.png)

Nhưng xài [graphql-voyager](https://graphql-kit.com/graphql-voyager/) thì nhìn cũng dễ hiểu rồi

![alt text](image-23.png)

Sau đó dễ dàng nhận ra là bảng `IAmNotHere` chính là nơi ta cần khai thác

Đầu tiên mình sẽ tạo một câu query đơn giản theo biểu đồ sau:

```graphql
query {
  IAmNotHere {
    very_long_id
    very_long_value
  }
}
```

Sau đó dùng [datafetcher](https://datafetcher.com/graphql-json-body-converter) để đổi query thuần sang json

```json
{
  "query": "query { IAmNotHere { very_long_id very_long_value }}"
}
```

![alt text](image-25.png)

OK từ đây ta biết được dòng very_long_id cần phải truyền giá trị vào

![alt text](image-26.png)

Vậy từ đây ta biết được rằng có lẽ flag được giấu trong các id này, bây giờ một là dùng tay, hai là intruder thôi

![alt text](image-27.png)

Sau khi dùng intruder để dò thử thì ở id 17 ta sẽ lấy được flag


# HTTP - cookies

Bài này lúc nào mình thấy không có gì để tương tác trên web lắm vào đọc src thì thấy cái này. Khi dùng chức năng save mail thì nó đòi mình là admin

![alt text](image-28.png)

Nên mình vào cookie editor sửa lại rồi save mail lần nữa là được

![alt text](image-29.png)

![alt text](image-30.png)

# JWT Introduction

Bài này khá đơn giản, chỉ cần thay username và alg là lấy được flag

![alt text](image-31.png)

# Directory Traversal 

![alt text](image-32.png)

vào trang web có param galerie để query tới các ảnh, nói chung bài này mình chỉ thử sai thôi chứ cũng không có idea gì.

![alt text](image-33.png)

Có giá trị `86hwnX2r` thì mình thử quăng vô thôi 
![alt text](image-34.png)

![alt text](image-35.png)

![alt text](image-36.png)

# File upload - Null byte

upload file php có dạng a.php%00.png thì sẽ qua sau đó vào file thì có flag

# JWT - revoked token

```python
    #!/usr/bin/env python3
    # -*- coding: utf-8 -*-
    from flask import Flask, request, jsonify
    from flask_jwt_extended import JWTManager, jwt_required, create_access_token, decode_token
    import datetime
    #from apscheduler.schedulers.background import BackgroundScheduler
    import threading
    import jwt
    from config import *
     
    # Setup flask
    app = Flask(__name__)
     
    app.config['JWT_SECRET_KEY'] = SECRET
    jwtmanager = JWTManager(app)
    blacklist = set()
    lock = threading.Lock()
     
    # Free memory from expired tokens, as they are no longer useful
    def delete_expired_tokens():
        with lock:
            to_remove = set()
            global blacklist
            for access_token in blacklist:
                try:
                    jwt.decode(access_token, app.config['JWT_SECRET_KEY'],algorithm='HS256')
                except:
                    to_remove.add(access_token)
           
            blacklist = blacklist.difference(to_remove)
     
    @app.route("/web-serveur/ch63/")
    def index():
        return "POST : /web-serveur/ch63/login <br>\nGET : /web-serveur/ch63/admin"
     
    # Standard login endpoint
    @app.route('/web-serveur/ch63/login', methods=['POST'])
    def login():
        try:
            username = request.json.get('username', None)
            password = request.json.get('password', None)
        except:
            return jsonify({"msg":"""Bad request. Submit your login / pass as {"username":"admin","password":"admin"}"""}), 400
     
        if username != 'admin' or password != 'admin':
            return jsonify({"msg": "Bad username or password"}), 401
     
        access_token = create_access_token(identity=username,expires_delta=datetime.timedelta(minutes=3))
        ret = {
            'access_token': access_token,
        }
       
        with lock:
            blacklist.add(access_token)
     
        return jsonify(ret), 200
     
    # Standard admin endpoint
    @app.route('/web-serveur/ch63/admin', methods=['GET'])
    @jwt_required
    def protected():
        access_token = request.headers.get("Authorization").split()[1]
        with lock:
            if access_token in blacklist:
                return jsonify({"msg":"Token is revoked"})
            else:
                return jsonify({'Congratzzzz!!!_flag:': FLAG})
     
     
    if __name__ == '__main__':
        scheduler = BackgroundScheduler()
        job = scheduler.add_job(delete_expired_tokens, 'interval', seconds=10)
        scheduler.start()
        app.run(debug=False, host='0.0.0.0', port=5000)
```

Bài này thì yêu cầu mình vào trang admin với JWT được tạo ở trên, nhưng ngặt nổi là token vừa tạo là vô blacklist luôn. Sau một hồi loay hoay thì mình có đi xin tí hint: **Có phải base64 lúc nào cũng kết thúc bởi dấu = không?**

Đây là [Post](https://stackoverflow.com/questions/6916805/why-does-a-base64-encoded-string-have-an-sign-at-the-end) mà mình đã đọc được trên stackoverflow giải thích khá rõ, về căn bản thì mỗi lần base64 decode nó sẽ chia cụm mỗi cụm 3 kí tự, nếu như thiếu thì nó sẽ padding thêm, mỗi kí tự thiếu là một dấu `=`

    abcdef => YWJjZGVm
    abcde  => YWJjZGU=
  
Vậy theo logic này thì `YWJjZGU=` = `YWJjZGU==` = `YWJjZGU`

Tiếp tục với bài làm thì khi mình vào /login thì không có giao diện để login nên mình dùng curl

```bash
curl -k -x http://127.0.0.1:8080 -X POST "http://challenge01.root-me.org/web-serveur/ch63/login" \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"admin"}'
```

Hoặc Burp

![alt text](image-37.png)

Burp có chức năng đổi từ `GET` thành `POST` request sau đó chỉ cần đổi content type và `POST` data là được.

Sau khi dùng token thì đúng như khi phân tích code nó đã expire
![alt text](image-38.png)

![alt text](image-39.png)

Sau đó mình thêm dấu = đằng sau thì đã lấy được flag

**Lưu ý:** làm trong khoảng 3 phút nếu thôi nó sẽ expire, mình nghĩ viết code python sẽ ok hơn


# JWT - Weak Secret

**Command:**`python3 jwt_tool.py <jwt_token> -C -d <wordlist>`

Với secret mình dùng 1 đoạn python để tạo ra token
```python
import jwt; print(jwt.encode({"role": "admin"}, "lol", algorithm="HS512", headers={"typ": "JWT", "alg": "HS512"}))

```

![alt text](image-40.png)

![alt text](image-41.png)