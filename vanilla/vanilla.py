import os, sqlite3
from flask import Flask, request, session, g, redirect, url_for, abort, \
     render_template, flash

app = Flask(__name__)
app.config.from_object(__name__)

app.config.update(dict(
	DATABASE = os.path.join(app.root_path, 'vanilla.db'),
	SECRET_KEY = 'development key',
	USERNAME = 'admin',
	PASSWORD = 'default'
))
app.config.from_envvar('VANILLA_SETTINGS', silent = True)

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

@app.route('/')
def show_home():
    db = get_db()
    return render_template('layout.html')
