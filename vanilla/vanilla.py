import os, sqlite3, re, flask_login
from flask import Flask, request, session, g, redirect, url_for, abort, \
     render_template, flash
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename


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


# Database Functions ###########################################################
def connect_db():
	rv = sqlite3.connect(app.config['DATABASE'])
	rv.row_factory = sqlite3.Row
	return rv

def init_db():
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()

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


# Command Line Functions #######################################################
@app.cli.command('insert-vendor')
def insert_vendor_command():
	v_name = input('Vendor Name: ')
	v_pw = bcrypt.generate_password_hash(input('Vendor Password: '))
	v_em = input('Vendor Email: ' )
	insert('vendors', ['vendorName', 'password', 'email'], [v_name, v_pw, v_em])
	print('Added', v_name, 'to vendors.')

@app.cli.command('initdb')
def initdb_command():
    init_db()
    print('Initialized the database.')


# User Functions ###############################################################
@login_manager.user_loader
def user_loader(id):
	return User(id[0], id[1])

def complete_login(id, cur_type):
	session['logged_in'] = True
	flask_login.login_user(User(id, cur_type))


# View Functions - Home ########################################################
@app.route('/')
def show_home():
	return render_template('home.html')

@app.route('/', methods = ['GET', 'POST'])
def login():
	error = None
	if request.method == 'POST' and request.form['action'] == 'login':
		req_em = request.form['email']
		req_pw = request.form['password']
		user = query_db('select * from users where email = ?', [req_em], True)
		vendor = query_db('select * from vendors where email = ?', [req_em], True)
		if user:
			if bcrypt.check_password_hash(user['password'], req_pw):
				complete_login(req_em, 'user')
				return render_template('home.html')
			else:
				error = 'Incorrect password for supplied email'
		elif vendor:
			if bcrypt.check_password_hash(vendor['password'], req_pw):
				complete_login(vendor['vendorName'], 'vendor')
				return render_template('home.html')
			else:
				error = 'wrong vendor password'
		else:
			error = 'Email does not exist in either database'
	elif request.method == 'POST' and request.form['action'] == 'signup':
		req_em = request.form['email']
		req_pw = request.form['password']
		valid_form = '^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$'
		valid_em = re.match(valid_form, req_em)
		if valid_em == None:
			error = 'SIGN-IN: Not a valid email address'
		elif req_pw:
			user = query_db('select * from users where email = ?', [req_em], True)
			vendor = query_db('select * from vendors where email = ?', [req_em], True)
			if not user and not vendor:
				enc_pw = bcrypt.generate_password_hash(req_pw)
				insert('users', ['password', 'email'], [enc_pw, req_em])
				complete_login(req_em, 'user')
				return render_template('home.html')
			else:
				error = 'Email already exists in database'
		else:
			error = 'No password supplied'
	return render_template('home.html', error = error)

# Add item to vendor page
def add_item(item_name, item_desc, item_img, vendor):
	folder = 'assets/' + vendor + '/'
	app.config['UPLOAD_FOLDER'] = folder
	fname = secure_filename(item_img.filename)
	full_path = folder + fname
	item_img.save(os.path.join(app.config['UPLOAD_FOLDER'], fname))
	insert('items', ['itemName', 'description', 'vendor', 'pathToImg'], \
		[item_name, item_desc, vendor, full_path])

# View Functions - Sample ######################################################
@app.route('/sample_vendor')
def show_sample_vendor():
	return render_template('sample_vendor.html')

@app.route('/sample_vendor', methods = ['GET', 'POST'])
def sample_vendor_add():
	if request.method == 'POST':
		item_name = request.form['itemName']
		item_desc = request.form['itemDesc']
		item_img = request.files['file']
		app.config['UPLOAD_FOLDER'] = 'assets/sample_vendor/'
		fname = secure_filename(item_img.filename)
		full_path = 'assets/sample_vendor/' + fname
		item_img.save(os.path.join(app.config['UPLOAD_FOLDER'], fname))
		insert('items', ['itemName', 'description', 'vendor', 'pathToImg'], \
			[item_name, item_desc, 'Dog Flat ', full_path])
	return redirect(url_for('show_sample_vendor'))

# View Functions - Store2 ######################################################


# View Functions - Logout ######################################################
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flask_login.logout_user()
    return redirect(url_for('show_home'))













