import os, sqlite3, re, flask_login
from flask import Flask, request, session, g, redirect, url_for, abort, \
     render_template, flash
from flask_bcrypt import Bcrypt

# Data types ###################################################################
class User(flask_login.UserMixin):
	def __init__(self, id, user_type = None):
		self.id = (id, user_type)

	def get_id(self):
		return (self.id[0], self.id[1])

# Application setup ############################################################
app = Flask(__name__)
app.config.from_object(__name__)

bcrypt = Bcrypt(app)

login_manager = flask_login.LoginManager()
login_manager.init_app(app)

app.config.update(dict(
	DATABASE = os.path.join(app.root_path, 'vanilla.db'),
	SECRET_KEY = 'development key' # TODO change me!
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
	cur = get_db()
	query = 'insert into %s (%s) values (%s)' % (
		table,
		', '.join(fields),
		', '.join(['?'] * len(values))
	)
	cur.execute(query, values)
	cur.commit()
	cur.close()

@app.cli.command('insert-vendor')
def insert_vendor_command():
	v_name = input('Vendor Name: ')
	v_pw = bcrypt.generate_password_hash(input('Vendor Password: '))
	v_em = input('Vendor Email: ' )
	insert('vendors', ['vendorName', 'password', 'email'], [v_name, v_pw, v_em])
	print('Added', v_name, 'to vendors.')

# User Functions ###############################################################
@login_manager.user_loader
def user_loader(id):
	return User(id[0], id[1])

def complete_login(id, cur_type):
	session['logged_in'] = True
	flask_login.login_user(User(id, cur_type))

# View functions ###############################################################
@app.route('/')
def show_home():
	return render_template('home.html')

@app.route('/sample_vendor')
def sample_vendor():
	return render_template('sample_vendor.html')

@app.route('/', methods = ['GET', 'POST'])
def login():
	error = None
	# Handle login POST requests
	if request.method == 'POST' and request.form['action'] == 'login':
		req_em = request.form['email']
		req_pw = request.form['password']
		# Query both databases
		user = query_db('select * from users where email = ?', [req_em], True)
		vendor = query_db('select * from vendors where email = ?', [req_em], True)
		# If the user exists
		if user:
			if bcrypt.check_password_hash(user['password'], req_pw):
				complete_login(req_em, 'user')
				return render_template('home.html')
			else:
				error = 'Incorrect password for supplied email'
		# If the vendor exists
		elif vendor:
			if bcrypt.check_password_hash(vendor['password'], req_pw):
				complete_login(vendor['vendorName'], 'vendor')
				return render_template('home.html')
			else:
				error = 'wrong vendor password'
		# Email doesn't exist in either table
		else:
			error = 'Email does not exist in either database'

	# Handle sign up POST requests
	elif request.method == 'POST' and request.form['action'] == 'signup':
		req_em = request.form['email']
		req_pw = request.form['password']
		# Assert email form is valid
		valid_form = '^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$'
		valid_em = re.match(valid_form, req_em)
		# Throw error if email is not valid
		if valid_em == None:
			error = 'SIGN-IN: Not a valid email address'
		# Check to see if a password was entered
		elif req_pw:
			# Query both databases
			user = query_db('select * from users where email = ?', [req_em], True)
			vendor = query_db('select * from vendors where email = ?', [req_em], True)
			# Create new user if the email doesn't exist in either table 
			if not user and not vendor:
				# Hash & salt password, store new user in table
				enc_pw = bcrypt.generate_password_hash(req_pw)
				insert('users', ['password', 'email'], [enc_pw, req_em])
				complete_login(req_em, 'user')
				return render_template('home.html')
			else:
				error = 'Email already exists in database'
		# Email was valid, but no password was supplied
		else:
			error = 'No password supplied'
	# Render home screen for non-valid POST requests
	return render_template('home.html', error = error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flask_login.logout_user()
    return redirect(url_for('show_home'))













