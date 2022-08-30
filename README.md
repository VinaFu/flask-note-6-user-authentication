# flask-note-6-user-authentication

这一章主要是介绍如何让输入的邮箱、名字不重复

1. 名字邮箱不重复：


      1.1 先在terminal里面建crypt：
      
            >>> from flask_bcrypt import Bcrypt
            >>> bcrypt = Bcrypt()
            >>> bcrypt.generate_password_hash('testing') 自动对应一串密码，开头的B代表了是B-crypt
            b'$2b$12$orUIZrCNVGEdG0uKtN9dpu4EJl9rxOQqHujKndeXbt28/XzRFrtF6'
            >>> bcrypt.generate_password_hash('testing').decode('utf-8'） 改成string结构在后面加上.decode('utf-8'）即可。
            '$2b$12$ktZrijndvBH22XWYNR8qE.nB7Kl3iqAHHjAmtgxzSeJRMfqdlivCi'
            >>> 但此时，每次出来的都是随机的一串密码，为了唯一性，操作如下：
            前面加了 hashed_pw =  ，后面用check属性来检查密码。所以现在我们的初始密码是testing。
            >>> hashed_pw =  bcrypt.generate_password_hash('testing').decode('utf-8')
            >>> bcrypt.check_password_hash(hashed_pw, 'passwor')
            False
            >>> bcrypt.check_password_hash(hashed_pw, 'testing')
            True
      
      
      1.2 然后回__init__.py 加入密码设置
      
            from flask_bcrypt import Bcrypt

            bcrypt = Bcrypt(app)
      
      
      
      1.3 routes.py 路径里面要增加数据命名和接收
      
            from flaskblog import app, db, bcrypt

            @app.route("/register", methods=["GET", "POST"])  去到注册表单里改写验证信息
            def register ():
                form = RegistrationForm()
                if form.validate_on_submit():
                    hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8') 先设密码
                    user = User(username=form.username.data, email=form.email.data, password=hashed_password) 设置用户信息
                    db.session.add(user) 
                    db.session.commit() 第4课，如何添加数据+确认添加
                    flash('Your account has been created! You are now able to log in',"success") 给小提示，如果成功，则进入下一步：
                    return redirect(url_for('login')) 转换至登陆界面
                return render_template('register.html',title="Register", form=form)
         
         
         
      1.4 forms.py 防止重复用户名和邮箱出现
      
            from wtforms.validators import 。。。 ValidationError
            from flaskblog.models import User
      
      在RegisterForm下面增加查重的功能：
      查用户名，所以里面变量也是用户名；if user:如果所选的信息存在，则提出错误“。。。”。这个操作比页面报错好很多！
      
            def validate_username(self, username):
             user = User.query.filter_by(username=username.data).first()
             if user:
                 raise ValidationError('That username is taken. Please choose a different one.')

            def validate_email(self, email):
             user = User.query.filter_by(email=email.data).first()
             if user:
                 raise ValidationError('That email is taken. Please choose a different one.')





