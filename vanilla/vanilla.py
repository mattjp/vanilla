import os, sqlite3
from flask import Flask, request, session, g, redirect, url_for, abort, \
     render_template, flash
from flask_bcrypt import Bcrypt
# from email_validator import validate_email, EmailNotValidError

# Application setup ############################################################
app = Flask(__name__)
app.config.from_object(__name__)
bcrypt = Bcrypt(app)

app.config.update(dict(
	DATABASE = os.path.join(app.root_path, 'vanilla.db'),
	SECRET_KEY = 'development key'
	# USERNAME = 'admin',
	# PASSWORD = 'default'
))
app.config.from_envvar('VANILLA_SETTINGS', silent = True)

# Database functions ###########################################################
def connect_db():
	rv = sqlite3.connect(app.config['DATABASE'])
	rv.row_factory = sqlite3.Row
	return rv

def init_db():
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()

@app.cli.command('initdb')
def initdb_command():
    init_db()
    print('Initialized the database.')

def get_db():
    if not hasattr(g, 'sqlite_db'):
        g.sqlite_db = connect_db()
    return g.sqlite_db

@app.teardown_appcontext
def close_db(error):
	if hasattr(g, 'sqlite_db'):
		g.sqlite_db.close()

def query_db(query, args = (), one = False):
	cur = get_db().execute(query, args)
	rv = cur.fetchall()
	cur.close()
	return (rv[0] if rv else None) if one else rv

def insert(table, fields = (), values = ()):
	# cur = g.db.cursor()
	cur = get_db()
	query = 'insert into %s (%s) values (%s)' % (
		table,
		', '.join(fields),
		', '.join(['?'] * len(values))
	)
	cur.execute(query, values)
	# g.db.commit()
	cur.commit()
	cur.close()

# View functions ###############################################################
@app.route('/')
def show_home():
    db = get_db()
    return render_template('home.html')

@app.route('/contact')
def show_contact():
	db = get_db()
	return render_template('contact.html')

@app.route('/', methods = ['GET', 'POST'])
def login():
	error = None
	if request.method == 'POST' and request.form['action'] == 'login':
		print('=== attempting login===')
		req_email = request.form['email']
		req_password = request.form['password']
		user = query_db('select * from users where email = ?', [req_email], True)
		if user:
			if bcrypt.check_password_hash(user['password'], req_password):
				session['logged_in'] = True
				flash('Successfully logged in')
				return redirect(url_for('show_contact'))
			else:
				error = 'Incorrect password'
		else:
			error = 'Not a valid email'
	elif request.method == 'POST' and request.form['action'] == 'signup':
		print('=== signing up ===')
		req_email = request.form['email']
		if request.form['password']:
			pw = bcrypt.generate_password_hash(request.form['password'])
			user = query_db('select * from users where email = ?', [req_email], True)
			if not user: # check if the email is valid AS WELL YOU IDIOT
				insert('users', ['password', 'email'], [pw, req_email])
				# try:
				# 	v = validate_email(req_email)
				# 	valid_email = v['email']
				# 	insert('users', [password, email], [pw, valid_email])
				# except EmailNotValidError as e:
				# 	print(str(e))
				# 	print('THAT AINT AN EMAIL')
			else:
				print('OOOOOOOOH FUCK THAT iS A USER ALREADY BRUH')
		else:
			print('you aint even got a password fuck outta here')
	return render_template('home.html', error = error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You were successfully logged out')
    return redirect(url_for('show_home'))













