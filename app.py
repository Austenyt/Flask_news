import hashlib

from flask import *

from models import User, News

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret key'


def password_hash(password):
    hash_object = hashlib.sha256(password.encode()).hexdigest()
    return hash_object


@app.before_request
def get_user():
    user_id = session.get('user_id')
    if user_id:
        user = User.get_or_none(User.id == user_id)
    else:
        user = None
    request.user = user


def render(template, **kwargs):
    return render_template(template, **kwargs, user=request.user)


@app.route('/')
def index():
    news = News.select().order_by(News.id.desc())
    return render('index.html', news=news)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render('register.html')
    else:
        email = request.form['email']
        password = request.form['password']
        password_confirm = request.form['password_confirm']
        if password != password_confirm:
            return render('register.html', error='Пароли не совпадают')
        try:
            User.create(
                email=email,
                password_hash=password_hash(password),
            )
            return redirect(url_for('index'))
        except Exception as error:
            return render('register.html', error=error)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render('login.html')
    else:
        email = request.form['email']
        password = request.form['password']
        user = User.get_or_none(User.email == email)

        if user:
            if user.password_hash == password_hash(password):
                session['user_id'] = user.id
                session['email'] = user.email
                return redirect(url_for('index'))
            else:
                return render('login.html', error='Неверный пароль')
        else:
            return render('login.html', error='Пользователь не найден')


@app.route('/add_post', methods=['GET', 'POST'])
def add_new():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        topic = request.form['topic']
        text = request.form['text']

        blog = News.create(
            topic=topic,
            text=text,
        )

        return redirect(url_for('index'))
    return render('add_new.html')


if __name__ == '__main__':
    app.run(debug=True)
