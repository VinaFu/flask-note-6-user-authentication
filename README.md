# flask-note-6-user-authentication

这一章主要是介绍如何让输入的邮箱、名字不重复

1. 名字邮箱不重复：

      先在terminal里面建crypt：
      >>> from flask_bcrypt import Bcrypt
      >>> bcrypt = Bcrypt()
      >>> bcrypt.generate_password_hash('testing') 自动对应一串密码，开头的B代表了是B-crypt
      b'$2b$12$orUIZrCNVGEdG0uKtN9dpu4EJl9rxOQqHujKndeXbt28/XzRFrtF6'
      >>> bcrypt.generate_password_hash('testing').decode('utf-8'） 改成string结构在后面加上.decode('utf-8'）即可。
      '$2b$12$ktZrijndvBH22XWYNR8qE.nB7Kl3iqAHHjAmtgxzSeJRMfqdlivCi'
      >>> 
