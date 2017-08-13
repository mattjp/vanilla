import os, sqlite3, re, flask_login
from flask import Flask, request, session, g, redirect, url_for, abort, \
     render_template, flash
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from collections import defaultdict, OrderedDict


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
	SECRET_KEY = 'development key', # TODO change me!
	MAIL_SERVER = 'smtp.gmail.com',
	MAIL_PORT = 587,
	MAIL_USE_TLS = True,
    MAIL_USE_SSL = False,
    MAIL_USERNAME = 'mjperetick@gmail.com',
    MAIL_PASSWORD = '' # Not putting this on GitHub
))
app.config.from_envvar('VANILLA_SETTINGS', silent = True)

mail = Mail(app)


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

def delete_from_db(query, args = ()):
	cur = get_db()
	cur.execute(query, args)
	cur.commit()
	cur.close()

def update_db(query, args = ()):
	cur = get_db()
	cur.execute(query, args)
	cur.commit()
	cur.close()


# Command Line Functions #######################################################
@app.cli.command('insert-vendor')
def insert_vendor_command():
	v_name = input('Vendor Name (shortened, no spaces): ')
	v_full_name = input('Vendor Name (Full): ')
	v_pw = bcrypt.generate_password_hash(input('Vendor Password: '))
	v_em = input('Vendor Email: ' )
	insert('vendors', ['vendorName', 'displayName', 'password', 'email'], \
		[v_name, v_full_name, v_pw, v_em])
	os.mkdir('static/' + v_name)
	print('Added', v_full_name, 'to vendors.')

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


# Helper Functions #############################################################
# Remove item from vendor page
def delete_item(item_name, vendor):
	path = query_db('select * from items where vendor = ? and itemName = ?', \
		[vendor, item_name], True)['pathToImg'][3:]
	print(path)
	os.remove(path)
	delete_from_db('delete from items where vendor = ? and itemName = ?', \
		[vendor, item_name])

# Add item to vendor page
def add_item(item_name, item_desc, item_img, vendor, item_price):
	exists = query_db('select * from items where itemName = ?', [item_name])
	# TODO this only kind of work
	# if exists:
	# 	print('CANNOT HAVE ITEMS WITH THE SAME NAME')
	# 	site = vendor + '.html'
	# 	return render_template(site, error = 'cannot have item with same name')
	folder = 'static/' + vendor + '/'
	app.config['UPLOAD_FOLDER'] = folder
	fname = secure_filename(item_img.filename)
	full_path = '../' + folder + fname
	item_img.save(os.path.join(app.config['UPLOAD_FOLDER'], fname))
	insert('items', ['itemName', 'description', 'vendor', 'pathToImg', 'price'], \
		[item_name, item_desc, vendor, full_path, item_price])

# Query the vendors database, display all vendors alphabetically
def find_all_vendors():
	all_vendors = query_db('select * from vendors')
	vendor_list = defaultdict(list)
	letters = []
	for vendor in all_vendors:
		if vendor['displayName'][0] not in letters:
			letters.append(vendor['displayName'][0])
	for vendor in all_vendors:
		vendor_list[vendor['displayName'][0]].append((vendor['vendorName'], \
			vendor['displayName']))
	for letter, vendor in vendor_list.items():
		vendor_list[letter.lower()] = vendor_list.pop(letter)
	vendor_list = OrderedDict(sorted((vendor_list).items()))
	for letter, vendor in vendor_list.items():
		vendor = vendor.sort()
	return vendor_list

# Sends an email
def send_email(subject, body):
	mail.send_message(subject = subject, body = body, \
		recipients = ['mjperetick@gmail.com'], \
		sender = ('Verdeckt', 'mjperetick@gmail.com'))

# Handles all requests that can come from the NavBar
def request_handler(request):
	error = None
	if request.method == 'POST' and request.form['action'] == 'login':
		req_em = request.form['email']
		req_pw = request.form['password']
		user = query_db('select * from users where email = ?', [req_em], True)
		vendor = query_db('select * from vendors where email = ?', [req_em], True)
		if user:
			if bcrypt.check_password_hash(user['password'], req_pw):
				complete_login(req_em, 'user')
				return error
			else:
				error = 'Incorrect password for supplied email'
		elif vendor:
			if bcrypt.check_password_hash(vendor['password'], req_pw):
				complete_login(vendor['vendorName'], 'vendor')
				return error
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
				return error
			else:
				error = 'Email already exists in database'
		else:
			error = 'No password supplied'
	elif request.method == 'POST' and request.form['action'] == 'change':
		user_id = flask_login.current_user.id[0]
		new_pw = bcrypt.generate_password_hash(request.form['new_password'])
		if flask_login.current_user.id[1] == 'user':
			update_db('update users set password = ? where email = ?', \
				[new_pw, user_id])
		else:
			update_db('update vendors set password = ? where vendorName = ?', \
				[new_pw, user_id])
	elif request.method == 'POST' and request.form['action'] == 'email':
		send_email(request.form['email_subject'], request.form['email_content'])
	return error
		

# View Functions - Home ########################################################
@app.route('/')
def show_home():
	return render_template('home.html')

@app.route('/', methods = ['GET', 'POST'])
def login():
	error = request_handler(request)
	return render_template('home.html', error = error)


# View Functions - Brands ######################################################
@app.route('/brands')
def show_all_brands():
	items = find_all_vendors()
	print(items)
	return render_template('brands.html', items = items)

@app.route('/brands', methods = ['GET', 'POST'])
def brands_request():
	error = request_handler(request)
	return redirect(url_for('show_all_brands')) # TODO: pass back the error somehow


# View Functions - Sample ######################################################
@app.route('/represent_clo')
def show_represent_clo():
	STORE = 'represent_clo'
	items = query_db('select * from items where vendor = ?', [STORE])
	return render_template('represent_clo.html', items = items)

@app.route('/represent_clo', methods = ['GET', 'POST'])
def update_represent_clo():
	STORE = 'represent_clo'
	error = request_handler(request)
	if request.method == 'POST' and flask_login.current_user.id[0] == STORE:
		if request.form['action'] == 'add_item':
			add_item(request.form['itemName'], request.form['itemDesc'], \
			request.files['file'], STORE, request.form['itemPrice'])
		elif request.form['action'] == 'del_item':
			delete_item(request.form['itemName'], STORE)
	return redirect(url_for('show_represent_clo'))


# View Functions - Store2 ######################################################
@app.route('/store2')
def show_store2():
	STORE = 'store2'
	items = query_db('select * from items where vendor = ?', [STORE])
	return render_template('store2.html', items = items)

@app.route('/store2', methods = ['GET', 'POST'])
def store2_update(): 
	STORE = 'store2'
	if request.method == 'POST' and flask_login.current_user.id[0] == STORE:
		if request.form['action'] == 'add_item':
			add_item(request.form['itemName'], request.form['itemDesc'], \
			request.files['file'], STORE, request.form['itemPrice'])
		elif request.form['action'] == 'del_item':
			delete_item(request.form['itemName'], STORE)
	return redirect(url_for('show_store2'))


# View Functions - Logout ######################################################
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flask_login.logout_user()
    return redirect(url_for('show_home'))


# Run Function #################################################################
if __name__ == '__main__':
	app.run()

