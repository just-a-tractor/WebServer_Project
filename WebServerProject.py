from wtforms import StringField, SubmitField, TextAreaField, PasswordField, BooleanField
from wtforms.validators import DataRequired
from flask_restful import reqparse, Api, Resource
from flask import Flask, render_template, redirect, session, jsonify, make_response
import sqlite3
from flask_wtf import FlaskForm

headerHtml = {'Content-Type': 'text/html'}


class LoginForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember_me = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')


app = Flask(__name__)
app.config['SECRET_KEY'] = 'yandexlyceum_secret_key'


class AddNewsForm(FlaskForm):
    title = StringField('Название корабля', validators=[DataRequired()])
    content = TextAreaField('Описание корабля', validators=[DataRequired()])


class DB:
    def __init__(self):
        conn = sqlite3.connect("sqlite/databases/mydb1.db", check_same_thread=False)
        self.conn = conn

    def get_connection(self):
        return self.conn

    def __del__(self):
        self.conn.close()


class UsersModel:
    def __init__(self, connection):
        self.connection = connection

    def init_table(self):
        cursor = self.connection.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users 
                            (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                             user_name VARCHAR(50),
                             password_hash VARCHAR(128)
                             )''')
        cursor.close()
        self.connection.commit()

    def insert(self, user_name, password_hash):
        cursor = self.connection.cursor()
        cursor.execute('''INSERT INTO users 
                          (user_name, password_hash) 
                          VALUES (?,?)''', (user_name, password_hash))
        cursor.close()
        self.connection.commit()

    def delete(self, user_id):
        cursor = self.connection.cursor()
        cursor.execute('''DELETE FROM users WHERE id = ?''', (str(user_id),))
        cursor.close()
        self.connection.commit()

    def get(self, user_id):
        cursor = self.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (str(user_id),))
        row = cursor.fetchone()
        return row

    def get_all(self):
        cursor = self.connection.cursor()
        cursor.execute('''select *, (select count(*) from news where news.user_id = users.id) as qty from users''')
        rows = cursor.fetchall()
        return rows

    def exists(self, user_name, password_hash):
        cursor = self.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE user_name = ? AND password_hash = ?",
                       (user_name, password_hash))
        row = cursor.fetchone()
        return (True, row[0]) if row else (False,)


"""class UsersModel:
    def __init__(self, connection):
        self.connection = connection

    def init_table(self):
        cursor = self.connection.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users 
                            (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                             user_name VARCHAR(50),
                             password_hash VARCHAR(128)
                             )''')
        cursor.close()
        self.connection.commit()

    def insert(self, user_name, password_hash):
        cursor = self.connection.cursor()
        cursor.execute('''INSERT INTO users 
                          (user_name, password_hash) 
                          VALUES (?,?)''', (user_name, password_hash))
        cursor.close()
        self.connection.commit()

    def get(self, user_id):
        cursor = self.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (str(user_id),))
        row = cursor.fetchone()
        return row

    def get_all(self):
        cursor = self.connection.cursor()
        cursor.execute('''select *, (select count(*) from news where news.user_id = users.id) as qty from users''')
        rows = cursor.fetchall()
        return rows

    def exists(self, user_name, password_hash):
        cursor = self.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE user_name = ? AND password_hash = ?",
                       (user_name, password_hash))
        row = cursor.fetchone()
        return (True, row[0]) if row else (False,)


class NewsModel:
    def __init__(self, connection):
        self.connection = connection

    def init_table(self):
        cursor = self.connection.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS news 
                            (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                             title VARCHAR(100),
                             content VARCHAR(1000),
                             user_id INTEGER
                             )''')
        cursor.close()
        self.connection.commit()

    def insert(self, title, content, user_id):
        cursor = self.connection.cursor()
        cursor.execute('''INSERT INTO news 
                          (title, content, user_id, Status) 
                          VALUES (?,?,?,?)''', (title, content, str(user_id), 'На проверке'))
        cursor.close()
        self.connection.commit()

    def get(self, news_id):
        cursor = self.connection.cursor()
        cursor.execute("SELECT * FROM news WHERE id = ?", (str(news_id),))
        row = cursor.fetchone()
        return row

    def get_all(self, user_id=None):
        cursor = self.connection.cursor()
        if user_id:
            cursor.execute("SELECT * FROM news WHERE user_id = ? ORDER BY id {}".format(session['srt']),
                           (str(user_id),))
        else:
            cursor.execute("SELECT * FROM news ORDER BY id {}".format(session['srt']))
        rows = cursor.fetchall()
        return rows

    def delete(self, news_id):
        cursor = self.connection.cursor()
        cursor.execute('''DELETE FROM news WHERE id = ?''', (str(news_id),))
        cursor.close()
        self.connection.commit()

    def change(self, u_id, status):
        cursor = self.connection.cursor()
        cursor.execute('''UPDATE news SET Status="{}" WHERE id={}'''.format(str(status).replace('%20', ' '), u_id))
        cursor.close()
        self.connection.commit()"""


class NewsModel:
    def __init__(self, connection):
        self.connection = connection

    def init_table(self):
        cursor = self.connection.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS news 
                            (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                             title VARCHAR(100),
                             content VARCHAR(1000),
                             user_id INTEGER
                             )''')
        cursor.close()
        self.connection.commit()

    def insert(self, title, content, user_id, user_name, image_url):
        cursor = self.connection.cursor()
        cursor.execute('''INSERT INTO news 
                          (title, content, user_id, user_name, image_url) 
                          VALUES (?,?,?,?,?)''', (title, content, str(user_id), user_name, image_url))
        cursor.close()
        self.connection.commit()

    def get(self, news_id):
        cursor = self.connection.cursor()
        cursor.execute("SELECT * FROM news WHERE id = ?", (str(news_id),))
        row = cursor.fetchone()
        return row

    def get_all(self, text='', sort=''):

        search = " WHERE title LIKE '%{}%'".format(text) if text else ""
        sort = " ORDER BY title {}".format(sort) if sort else ""
        sql = "SELECT * FROM news " + search + sort

        cursor = self.connection.cursor()
        cursor.execute(sql)
        rows = cursor.fetchall()
        return rows

    def delete(self, news_id):
        cursor = self.connection.cursor()
        cursor.execute('''DELETE FROM news WHERE id = ?''', (str(news_id),))
        cursor.close()
        self.connection.commit()

    def change_status(self, u_id, status):
        cursor = self.connection.cursor()
        cursor.execute('''UPDATE news SET Status="{}" WHERE id={}'''.format(str(status).replace('%20', ' '), u_id))
        cursor.close()
        self.connection.commit()

    def change_text(self, news_id, type1, new_text):
        cursor = self.connection.cursor()
        if type1 == 'title':
            cursor.execute('''UPDATE news SET title="{}" WHERE id={}'''.format(new_text, news_id))
        else:
            cursor.execute('''UPDATE news SET content="{}" WHERE id={}'''.format(new_text, news_id))
        cursor.close()
        self.connection.commit()


def abort_if_news_not_found(news_id):
    if not NewsModel(db.get_connection()).get(news_id):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('404.html'), 200, headers)


def abort_if_user_not_found(user_id):
    if not UsersModel(db.get_connection()).get(user_id):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('404.html'), 200, headers)


parser = reqparse.RequestParser()

parser.add_argument('title', required=True)
parser.add_argument('content', required=True)
parser.add_argument('file', required=False)

parser1 = reqparse.RequestParser()
parser1.add_argument('user_name', required=True)
parser1.add_argument('password_hash', required=True)

parserS = reqparse.RequestParser()
parserS.add_argument('search1', required=False)
parserS.add_argument('sort', required=False)


class User(Resource):
    def get(self):
        session.pop('username', 0)
        session.pop('user_id', 0)
        form = LoginForm()
        session['srt'] = ''
        return make_response(render_template('index1.html', title='Авторизация', form=form), 200, headerHtml)

    def post(self):
        form = LoginForm()
        user_name = form.username.data
        password = form.password.data
        exists = user_model.exists(user_name, password)
        if exists[0]:
            session['username'] = user_name
            session['user_id'] = exists[1]
        return redirect("/")

    def delete(self, user_id):
        abort_if_user_not_found(user_id)
        UsersModel(db.get_connection()).delete(user_id)
        return jsonify({'success': 'OK'})


class UsersList(Resource):
    def get(self):
        form = LoginForm()
        session.pop('username', 0)
        session.pop('user_id', 0)
        return make_response(render_template('index1.html', title='Регистация', form=form), 200, headerHtml)

    def post(self):
        form = LoginForm()
        user_name = form.username.data
        if user_name != 'Admin':
            password = form.password.data
            exists = user_model.exists(user_name, password)
            if not exists[0]:
                session['username'] = user_name
                user_model.insert(user_name, password)
                exists = user_model.exists(user_name, password)
                if exists[0]:
                    session['username'] = user_name
                    session['user_id'] = exists[1]
            else:
                return redirect('/reg')

            return redirect("/")
        else:
            return redirect('/reg')


# ------------------------------------------------------------------>


class News(Resource):
    def get(self, news_id=None):

        if news_id:
            abort_if_news_not_found(news_id)
            news = NewsModel(db.get_connection()).get(news_id)
            headers = {'Content-Type': 'text/html'}
            return make_response(render_template('read_news.html', news=news), 200, headers)
        else:
            form = AddNewsForm()
            if form.validate_on_submit():
                title = form.title.data
                content = form.content.data
                file = form.file.data
                nm = NewsModel(db.get_connection())
                url = file  # 'static/large/apocalypse.jpg'
                nm.insert(title, content, session['user_id'], session['username'], url)
                return redirect('/')
            return make_response(render_template('add_news1.html', title='Ваша статья', form=form))

    def post(self):
        pa = parser.parse_args()
        url = '/static/large/' + pa['file']
        NewsModel(db.get_connection()).insert(pa['title'], pa['content'], session['user_id'], session['username'], url)
        return redirect("/")

    def delete(self, news_id):
        abort_if_news_not_found(news_id)
        NewsModel(db.get_connection()).delete(news_id)
        return jsonify({'success': 'OK'})


class NewsList(Resource):
    def get(self, p=False):

        if 'username' not in session:
            return redirect('/login')

        if p == 1:
            session['srt'] = 'desc' if not session['srt'] else ''

        nm = NewsModel(db.get_connection())
        news = nm.get_all()

        return make_response(render_template('main1.html', news=news), 200, headerHtml)

    def post(self):
        p = parserS.parse_args()
        nm = NewsModel(db.get_connection())

        txt_param = ''
        srt_param = ''

        if 'search1' in p and p['search1']:
            txt_param = p['search1']

        if 'sort' in p:
            srt_param = p['sort']

        news = nm.get_all(text=txt_param, sort=srt_param)

        return make_response(render_template('main1.html', news=news), 200, headerHtml)


db = DB()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'yandexlyceum_secret_key'
api = Api(app)

api.add_resource(NewsList, '/news1/<int:p>', '/news1', '/')  # для списка объектов, но со "/"
api.add_resource(News, '/news/<int:news_id>', '/news')  # для одного объекта

api.add_resource(UsersList, '/reg', '/login/<int:user_id>')  # для списка объектов
api.add_resource(User, '/login')  # для одного объекта

user_model = UsersModel(db.get_connection())


if __name__ == '__main__':
    app.run(port=8080, host='127.0.0.1')
