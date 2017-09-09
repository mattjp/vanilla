import os, sqlite3, re, flask_login, calendar
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

PROJECT_ROOT = os.path.dirname(os.path.realpath(__file__))
ADMIN = 'verdeckt_admin'

app.config.update(dict(
	DATABASE = os.path.join(PROJECT_ROOT, 'vanilla.db'),
	SECRET_KEY = 'knuckle puck crew fuck you', 
	MAIL_SERVER = 'email-smtp.us-east-1.amazonaws.com',
	MAIL_PORT = 25,
	MAIL_USE_TLS = True,
	MAIL_USERNAME = 'AKIAIRG2N35PPM6V52FA',
	MAIL_PASSWORD = 'AvKIR1CCbqDMDwRBIQId1jJKU57P6THRb4wvIpK24SlD'
))

app.config.from_envvar('VANILLA_SETTINGS', silent = True)
mail = Mail(app)


# Database Functions ###########################################################
def connect_db():
	rv = sqlite3.connect('/var/www/html/vanilla/vanilla.db') # TODO: Server Path
	# rv = sqlite3.connect(app.config['DATABASE'])
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
# Creates vendor in table with no email or password
@app.cli.command('create-vendor')
def create_vendor_command():
	v_name = input('Vendor Name (shortened, no spaces): ')
	v_full_name = input('Vendor Name (Full): ')
	type_1 = input('First type (can be empty): ')
	type_2 = input('Second type (can be empty): ')
	type_3 = input('Third type (can be empty): ')
	loc = input('Location: ')
	shipping = input('Shipping (make sure it ends with \'shipping\'): ')
	category = input('Vendor size (make sure it ends with \'staff\'): ')
	insert('vendors', ['vendorName', 'displayName', 'type_1', 'type_2', 'type_3', \
		'loc', 'shipping', 'category'], [v_name, v_full_name, type_1, type_2, \
		type_3, loc, shipping, category])
	os.mkdir('static/' + v_name)
	# Add a small text file so GitHub will upload the directory
	os.system('echo ' + v_name + ' > ' + 'static/' + v_name + '/' + v_name + '.txt')
	print('Added', v_full_name, 'to vendors.')

# Creates vendor in the table with all columns filled out
@app.cli.command('create-vendor-full')
def create_vendor_full_command():
	v_name = input('Vendor Name (shortened, no spaces): ')
	v_full_name = input('Vendor Name (Full): ')
	v_em = input('Vendor Email: ' )
	v_pw = bcrypt.generate_password_hash(input('Vendor Password: '))
	type_1 = input('First type (can be empty): ')
	type_2 = input('Second type (can be empty): ')
	type_3 = input('Third type (can be empty): ')
	loc = input('Location: ')
	shipping = input('Shipping (make sure it ends with \'shipping\'): ')
	category = input('Vendor size: ')
	insert('vendors', ['vendorName', 'displayName', 'email', 'password', 'type_1', \
		'type_2', 'type_3', 'loc', 'shipping', 'category'], [v_name, v_full_name, \
		v_em, v_pw, type_1, type_2, type_3, loc, shipping, category])
	os.mkdir('static/' + v_name)
	print('Added', v_full_name, 'to vendors.')

# Adds email and password to the specified vendor
@app.cli.command('update-vendor-details')
def update_vendor_details_command():
	v_name = input('Vendor Name (shortened, no spaces): ')
	v_em = input('Vendor Email: ' )
	v_pw = bcrypt.generate_password_hash(input('Vendor Password: '))
	update_db('update vendors set email = ?, password = ? where vendorName = ?', \
		[v_em, v_pw, v_name])
	print('Added email and password to', v_name)

# Creates Database tables if they don't exist
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
	full_path = '/var/www/html/vanilla/' + path # TODO: Server path
	os.remove(full_path) # TODO: Server version
	# os.remove(path)
	delete_from_db('delete from items where vendor = ? and itemName = ?', \
		[vendor, item_name])

# Add item to vendor page
def add_item(item_name, item_desc, item_img, vendor, item_price):
	exists = query_db('select * from items where itemName = ? and vendor = ?', \
		[item_name, vendor])
	if exists:
		return 'Cannot have items with the same name'
	folder = 'static/' + vendor + '/'
	app.config['UPLOAD_FOLDER'] = folder
	fname = secure_filename(item_img.filename)
	full_path = '../' + folder + fname
	item_img.save('/var/www/html/vanilla/' + folder + fname) # TODO: Server path
	# item_img.save(os.path.join(app.config['UPLOAD_FOLDER'], fname))
	insert('items', ['itemName', 'description', 'vendor', 'pathToImg', 'price'], \
		[item_name, item_desc, vendor, full_path, item_price])
	return None

# Query the vendors database, display all vendors alphabetically
def find_all_vendors():
	all_vendors = query_db("select * from vendors where vendorName != 'verdeckt_admin'")
	vendor_list = defaultdict(list)
	letters = []
	for vendor in all_vendors:
		if vendor['vendorName'][0] not in letters:
			letters.append(vendor['vendorName'][0])
	for vendor in all_vendors:
		vendor_list[vendor['vendorName'][0]].append((vendor['vendorName'], \
			vendor['displayName']))
	vendor_list = OrderedDict(sorted((vendor_list).items()))
	for letter, vendor in vendor_list.items():
		vendor = vendor.sort()
	return vendor_list

# Sends an email
def send_email(subject, body):
	mail.send_message(subject = subject, body = body, \
		recipients = ['mattp@verdeckt.com', 'chrisz@verdeckt.com'], \
		sender = ('Verdeckt Support', 'mattp@verdeckt.com'))

# Handles all requests that can come from the nav-bar
def request_handler(request):
	error = None
	# Handle login requests
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
				error = 'wrong username/password'
		elif vendor:
			if bcrypt.check_password_hash(vendor['password'], req_pw):
				complete_login(vendor['vendorName'], 'vendor')
				return error
			else:
				error = 'wrong username/password'
		else:
			error = 'no such email'
	# Handle sign-up requests
	elif request.method == 'POST' and request.form['action'] == 'signup':
		req_em = request.form['email']
		req_pw = request.form['password']
		valid_form = '^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$'
		valid_em = re.match(valid_form, req_em)
		if valid_em == None and req_em != ADMIN:
			error = 'not a valid email'
		elif req_pw:
			user = query_db('select * from users where email = ?', [req_em], True)
			vendor = query_db('select * from vendors where email = ?', [req_em], True)
			if not user and not vendor:
				enc_pw = bcrypt.generate_password_hash(req_pw)
				insert('users', ['password', 'email'], [enc_pw, req_em])
				complete_login(req_em, 'user')
				return error
			else:
				error = 'email already exists'
		else:
			error = 'no password supplied'
	# Handle change requests
	elif request.method == 'POST' and request.form['action'] == 'change':
		user_id = flask_login.current_user.id[0]
		new_pw = bcrypt.generate_password_hash(request.form['new_password'])
		if flask_login.current_user.id[1] == 'user':
			update_db('update users set password = ? where email = ?', \
				[new_pw, user_id])
		else:
			update_db('update vendors set password = ? where vendorName = ?', \
				[new_pw, user_id])
	# Handle send-email requests
	elif request.method == 'POST' and request.form['action'] == 'email':
		send_email(request.form['email_subject'], request.form['email_content'])
	# Return any errors 
	return error

# Show a vendor page
def show_vendor(vendor):
	addr = vendor + '.html'
	items = query_db('select * from items where vendor = ?', [vendor])
	brand = query_db('select * from vendors where vendorName = ?', [vendor], True)
	return render_template(addr, items = items, brand = brand)

# Handle requests for a vendor page
def vendor_request_handler(vendor, request):
	addr = vendor + '.html'
	redir = 'show_' + vendor
	error = request_handler(request)
	if error: 
		items = query_db('select * from items where vendor = ?', [vendor])
		brand = query_db('select * from vendors where vendorName = ?', [vendor], True)
		return render_template(addr, error = error, items = items, brand = brand)
	elif request.method == 'POST' and (flask_login.current_user.id[0] == vendor or \
		flask_login.current_user.id[0] == ADMIN):
		# Add item requests
		if request.form['action'] == 'add_item':
			price_with_symbol = request.form['currency_type'] + \
				request.form['itemPrice']
			error = add_item(request.form['itemName'], request.form['itemDesc'], \
			request.files['file'], vendor, price_with_symbol)
			if error:
				items = query_db('select * from items where vendor = ?', [vendor])
				brand = query_db('select * from vendors where vendorName = ?', [vendor], True)
				return render_template(addr, error = error, items = items, brand = brand)
		# Delete item requests
		elif request.form['action'] == 'del_item':
			delete_item(request.form['itemName'], vendor)
		# Add drop date requests
		elif request.form['action'] == 'add_drop':
			exists = query_db('select * from drops where dropVendor = ?', [vendor])
			if exists: 
				error = 'cannot have more than one (1) drop'
				items = query_db('select * from items where vendor = ?', [vendor])
				brand = query_db('select * from vendors where vendorName = ?', [vendor], True)
				return render_template(addr, error = error, items = items, brand = brand)
			date = request.form['drop_date'].split(' \\ ')
			date[1] = calendar.month_name[int(date[1])][:3]
			time = request.form['drop_time'] + ':00'
			js_date = date[1] + ' ' + date[0] + ', ' + date[2] + ' ' + time
			yes = 'True'
			insert('drops', ['dropVendor', 'dropDate'], [vendor, js_date])
			# update_db('update vendors set hasDrop = ? where vendorName = ?', \
				# [yes, vendor])
	return redirect(url_for(redir))


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
	return redirect(url_for('show_all_brands'))


# View Functions - Individual Vendors ##########################################
# Alphamotif
@app.route('/alphamotif')
def show_alphamotif():
	return show_vendor('alphamotif')

@app.route('/alphamotif', methods = ['GET', 'POST'])
def update_alphamotif(): 
	return vendor_request_handler('alphamotif', request)

# ASHORE
@app.route('/ashore')
def show_ashore():
	return show_vendor('ashore')

@app.route('/ashore', methods = ['GET', 'POST'])
def update_ashore(): 
	return vendor_request_handler('ashore', request)

# Atelier LPM
@app.route('/atelier_lpm')
def show_atelier_lpm():
	return show_vendor('atelier_lpm')

@app.route('/atelier_lpm', methods = ['GET', 'POST'])
def update_atelier_lpm(): 
	return vendor_request_handler('atelier_lpm', request)

# BitterSweet
@app.route('/bittersweet')
def show_bittersweet():
	return show_vendor('bittersweet')

@app.route('/bittersweet', methods = ['GET', 'POST'])
def update_bittersweet(): 
	return vendor_request_handler('bittersweet', request)

# Bomb Clothing Co.
@app.route('/bomb_clo_co')
def show_bomb_clo_co():
	return show_vendor('bomb_clo_co')

@app.route('/bomb_clo_co', methods = ['GET', 'POST'])
def update_bomb_clo_co(): 
	return vendor_request_handler('bomb_clo_co', request)

# Deadnight
@app.route('/deadnight')
def show_deadnight():
	return show_vendor('deadnight')

@app.route('/deadnight', methods = ['GET', 'POST'])
def update_deadnight(): 
	return vendor_request_handler('deadnight', request)

# Gloomy Season
@app.route('/gloomy_season')
def show_gloomy_season():
	return show_vendor('gloomy_season')

@app.route('/gloomy_season', methods = ['GET', 'POST'])
def update_gloomy_season(): 
	return vendor_request_handler('gloomy_season', request)

# Guerrilla Group
@app.route('/guerrilla_group')
def show_guerrilla_group():
	return show_vendor('guerrilla_group')

@app.route('/guerrilla_group', methods = ['GET', 'POST'])
def update_guerrilla_group(): 
	return vendor_request_handler('guerrilla_group', request)

# Guilt Association
@app.route('/guilt_association')
def show_guilt_association():
	return show_vendor('guilt_association')

@app.route('/guilt_association', methods = ['GET', 'POST'])
def update_guilt_association(): 
	return vendor_request_handler('guilt_association', request)

# Leftovers
@app.route('/leftovers')
def show_leftovers():
	return show_vendor('leftovers')

@app.route('/leftovers', methods = ['GET', 'POST'])
def update_leftovers(): 
	return vendor_request_handler('leftovers', request)

# Lordz
@app.route('/lordz')
def show_lordz():
	return show_vendor('lordz')

@app.route('/lordz', methods = ['GET', 'POST'])
def update_lordz(): 
	return vendor_request_handler('lordz', request)

# Maharishi
@app.route('/maharishi')
def show_maharishi():
	return show_vendor('maharishi')

@app.route('/maharishi', methods = ['GET', 'POST'])
def update_maharishi(): 
	return vendor_request_handler('maharishi', request)

# Marble Soda
@app.route('/marble_soda')
def show_marble_soda():
	return show_vendor('marble_soda')

@app.route('/marble_soda', methods = ['GET', 'POST'])
def update_marble_soda(): 
	return vendor_request_handler('marble_soda', request)

# OH Boi
@app.route('/oh_boi')
def show_oh_boi():
	return show_vendor('oh_boi')

@app.route('/oh_boi', methods = ['GET', 'POST'])
def update_oh_boi(): 
	return vendor_request_handler('oh_boi', request)

# Pearly Whites
@app.route('/pearly_whites')
def show_pearly_whites():
	return show_vendor('pearly_whites')

@app.route('/pearly_whites', methods = ['GET', 'POST'])
def update_pearly_whites(): 
	return vendor_request_handler('pearly_whites', request)

# Ronin Division
@app.route('/ronin_division')
def show_ronin_division():
	return show_vendor('ronin_division')

@app.route('/ronin_division', methods = ['GET', 'POST'])
def update_ronin_division(): 
	return vendor_request_handler('ronin_division', request)

# Rude Vogue
@app.route('/rude_vogue')
def show_rude_vogue():
	return show_vendor('rude_vogue')

@app.route('/rude_vogue', methods = ['GET', 'POST'])
def update_rude_vogue(): 
	return vendor_request_handler('rude_vogue', request)

# Seance Clothing
@app.route('/seance_clothing')
def show_seance_clothing():
	return show_vendor('seance_clothing')

@app.route('/seance_clothing', methods = ['GET', 'POST'])
def update_seance_clothing(): 
	return vendor_request_handler('seance_clothing', request)

# Song for the Mute
@app.route('/song_for_the_mute')
def show_song_for_the_mute():
	return show_vendor('song_for_the_mute')

@app.route('/song_for_the_mute', methods = ['GET', 'POST'])
def update_song_for_the_mute(): 
	return vendor_request_handler('song_for_the_mute', request)

# Steady Hands Apparel
@app.route('/steady_hands_apparel')
def show_steady_hands_apparel():
	return show_vendor('steady_hands_apparel')

@app.route('/steady_hands_apparel', methods = ['GET', 'POST'])
def update_steady_hands_apparel(): 
	return vendor_request_handler('steady_hands_apparel', request)

# The MSTRPLAN
@app.route('/the_mstrplan')
def show_the_mstrplan():
	return show_vendor('the_mstrplan')

@app.route('/the_mstrplan', methods = ['GET', 'POST'])
def update_the_mstrplan(): 
	return vendor_request_handler('the_mstrplan', request)

# VVIDessnce
@app.route('/vvidessnce')
def show_vvidessnce():
	return show_vendor('vvidessnce')

@app.route('/vvidessnce', methods = ['GET', 'POST'])
def update_vvidessnce(): 
	return vendor_request_handler('vvidessnce', request)

# Windfall Clothing
@app.route('/windfall_clothing')
def show_windfall_clothing():
	return show_vendor('windfall_clothing')

@app.route('/windfall_clothing', methods = ['GET', 'POST'])
def update_windfall_clothing(): 
	return vendor_request_handler('windfall_clothing', request)


# View Functions - Logout ######################################################
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flask_login.logout_user()
    return redirect(url_for('show_home'))


# Run Function #################################################################
if __name__ == '__main__':
	app.run(host='0.0.0.0') # TODO: Server run
	# app.run(debug = True)

