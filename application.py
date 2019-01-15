import json
import logging
import random
import string

import httplib2
import requests
from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from flask import make_response
from flask import session as login_session
from oauth2client.client import FlowExchangeError
from oauth2client.client import flow_from_clientsecrets
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session

from database_setup import Base, User, Category, CatalogItem


app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "CatalogApp"

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

session = scoped_session(sessionmaker(bind=engine))


@app.teardown_appcontext
def shutdown_session(exception=None):
    session.remove()


@app.route('/login')
def show_login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    logging.info("access token received %s " % access_token)

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_id']
    app_secret = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_' \
          'id=%s&client_secret=%s&fb_exchange_token=%s' % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    login_session['access_token'] = token

    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    user_id = get_user_id(login_session['email'])

    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: ' \
              '150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]

    if result['status'] == '200':
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['facebook_id']
        return redirect(url_for('show_catalog'), "you have been logged out")
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    code = request.data
    try:
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        logging.error("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = json.loads(answer.text)

    login_session['username'] = data["name"]
    login_session['picture'] = data["picture"]
    login_session['email'] = data["email"]

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;' \
              '-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    logging.error("done!")
    return output


def create_user(login_session):
    new_user = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def get_user_info(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def get_user_id(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        logging.error('Access Token is None')
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    logging.info('In gdisconnect access token is %s', access_token)
    logging.info('User name is: ')
    logging.info(login_session['username'])

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    logging.info('URL=', url)
    result = h.request(url, 'POST')[0]
    logging.info('result is ')
    logging.info(result)
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return redirect('/')
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/categories/<int:category_id>/items/JSON')
def category_items_json(category_id):
    items = session.query(CatalogItem).filter_by(category_id=category_id).all()
    return jsonify(Items=[i.serialize for i in items])


@app.route('/categories/<int:category_id>/items/<int:item_id>/JSON')
def item_json(item_id):
    item = session.query(CatalogItem).filter_by(id=item_id).one()

    return jsonify(Item=item.serialize)


@app.route('/JSON')
def categories_json():
    categories = session.query(Category).all()

    return jsonify(categories=[c.serialize for c in categories])


@app.route('/')
def show_catalog():
    categories = session.query(Category).all()
    # show last 10 added items
    items = session.query(CatalogItem).order_by(CatalogItem.date).limit(10)

    return render_template('catalog.html', categories=categories, items=items)


@app.route('/categories/<int:category_id>/')
@app.route('/categories/<int:category_id>/items/')
def show_items(category_id):
    categories = session.query(Category).all()
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(CatalogItem).filter_by(category_id=category_id).all()

    return render_template('Items.html', items=items, category=category, categories=categories,
                           active_category_id=category_id)


@app.route('/categories/<int:category_id>/items/<int:item_id>/')
def show_item(category_id, item_id):
    category = session.query(Category).filter_by(id=category_id).one()
    item = session.query(CatalogItem).filter_by(id=item_id).one()

    if 'username' not in login_session:
        return render_template('publicitem.html', item=item, category=category)
    else:
        return render_template('item.html', item=item, category=category)


@app.route('/new/', methods=['GET', 'POST'])
def new_item():
    if 'username' not in login_session:
        return redirect('/login')

    categories = session.query(Category).all()

    if request.method == 'POST':
        user_id = get_user_id(login_session['email'])
        new_item = CatalogItem(
            name=request.form['name'], description=request.form['description'], category_id=request.form['category_id'],
            user_id=user_id)
        session.add(new_item)
        flash('New Item %s Successfully Created' % new_item.name)
        session.commit()
        return redirect(url_for('show_catalog'))
    else:
        return render_template('newItem.html', categories=categories)


@app.route('/categories/<int:category_id>/items/<int:item_id>/edit', methods=['GET', 'POST'])
def edit_item(category_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')

    user_id = get_user_id(login_session['email'])
    edited_item = session.query(CatalogItem).filter_by(id=item_id).one()

    if user_id != edited_item.user_id:
        return render_template('notauthorizedmsg.html', category_id=category_id, item_id=item_id, item=edited_item)
    categories = session.query(Category).all()

    if request.method == 'POST':
        if request.form['name']:
            edited_item.name = request.form['name']
        if request.form['description']:
            edited_item.description = request.form['description']
            edited_item.category_id = request.form['category_id']
        session.add(edited_item)
        session.commit()
        flash('Item Successfully Edited')
        return redirect(url_for('show_items', category_id=category_id))
    else:
        return render_template('edititem.html', category_id=category_id, item_id=item_id, item=edited_item,
                               categories=categories)


@app.route('/categories/<int:category_id>/items/<int:item_id>/delete', methods=['GET', 'POST'])
def delete_item(category_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')
    user_id = get_user_id(login_session['email'])
    item_to_delete = session.query(CatalogItem).filter_by(id=item_id).one()

    if user_id != item_to_delete.user_id:
        return render_template('notauthorizedmsg.html', category_id=category_id, item_id=item_id, item=item_to_delete)
    if request.method == 'POST':
        session.delete(item_to_delete)
        session.commit()
        flash('Item Successfully Deleted')
        return redirect(url_for('show_items', category_id=category_id))
    else:
        return render_template('deleteItem.html', item=item_to_delete, category_id=category_id)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
