from flask import Flask, render_template, request, redirect,jsonify, url_for, flash
app = Flask(__name__)

from sqlalchemy import create_engine, asc, and_, or_, desc
from sqlalchemy.orm import sessionmaker
from database import Base, User, Asset, OrderBook

#System libraries
import datetime

#Libraries to generate a session and to generate random numbers as token CSRF
from flask import session as login_session
import random, string

#Libraries to use oauth2
from oauth2client.client import flow_from_clientsecrets #JSON formatted style stores clientid, client secret, and Oauth2 param.
from oauth2client.client import FlowExchangeError #catch an error trying to exchange an auth code for an access token
import httplib2 #Client HTTP library
import json #Serialize Python Objects in JSON Format
from flask import make_response #convert the return value from a function into a response object that is send off to the client.
import requests #Apache 2.0 licensed Http library to call URLs 

CLIENT_ID = json.loads(
    open('client_secrets.json','r').read()) ['web']['client_id']

#Connect to Database and create database session
engine = create_engine('sqlite:///motoremparejamiento.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

#Create a state token to prevent request forgery.
#Store it in the session for later validation.
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)

#Connect with Google Oauth API
@app.route('/gconnect', methods=['POST'])
def gconnect():
        #Validate the CSRF token as arg in the URL and compare with the state generated in ShowLogin.
    if request.args.get('state') != login_session['state']:
        #If this is not valid, make a response indicating te parameter is invalid and return the code 401.
        response = make_response(json.dumps('Invalid state parameters'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Colect the One Time Code from the client.
    code = request.data
    #Try to use the One Time Code and exchange it for Credentials Object.
    try:
        #Upgrade the auth code into credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='') #Creates an OauthFlow Object to Add client secret_key information.
        oauth_flow.redirect_uri = 'postmessage' #With postmessage specify this is the one time code the server will be sending off.
        credentials = oauth_flow.step2_exchange(code) #Exchange an authorization code for a credentials object.
    except FlowExchangeError:
        #Catch and manage the error
        response = make_response(json.dumps('failed to upgrade the authorization code'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    
    #check that the access token is valid
    access_token = credentials.access_token
    #with this URL and the acces token appended. Verify this is a valid token.
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
    #With the following line Create a json with the result of the get request contanining the url  and the acess token.
    h = httplib2.Http()
    result = json.loads(h.request(url,'GET')[1])
    
    #if there was an error in the result because access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    #Verify that access token is used for the intented user
    #Here the token is stored from credentials object and compare with the user_id by the google URL.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("token's user id doesn't match given user_id."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    
    #Check if the token has the same client id associated with the APP.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("token's client id doesn't match app's."), 401)
        print ("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response
    #Check if user is already logged in 
    stored_credentials = login_session.get('access_token')
    stored_gplusid = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplusid:
        response = make_response(json.dumps('Current user is already connected'), 200)
        response.headers['Content-Type'] = 'application/json'
    #after the validation i have a valid and new access token.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id
    #Get the user info from Google API
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token':credentials.access_token, 'alt':'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']


    user_id = getUserID(login_session['email'])
    '''
    print user_id
    if user_id is not None:
        user = getUserInfo(user_id)
        session.delete(user)
    asset_name = "Asset_" + str(user_id)
    asset_id = getAssetID(asset_name)
    print asset_id
    if asset_id is not None:    
        asset = session.query(Asset).filter_by(name = asset_name).first()
        session.delete(asset)
    user_id = getUserID(login_session['email'])
    asset_id = getAssetID(asset_name)
    print user_id
    print asset_id
    '''
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id


    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print ("done!")
    return output

#DISCONNECT - Revoke a currents user token and reset their login session.
@app.route("/gdisconnect")
def gdisconnect():
    #Only disconnect a connected user
    access_token = login_session.get('access_token')
    if access_token is None:
        #response = make_response(json.dumps('current user not connected'), 401)
        #response.headers['Content-Type'] = 'application/json'
        flash('current user not connected')
        return redirect ('/index')
    #Execute HTTP GET request to revoke current token
    url = ('https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token)
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # reset the users session
        login_session.clear()
        #response = make_response(json.dumps('Succesfully disconnected.'), 200)
        #response.headers ["Content-Type"] = "application/json"
        #return response
        flash('Succesfully disconnected.')
        return redirect ('/index')
    else:
        # reset the users session
        login_session.clear()
        #response = make_response(json.dumps('failed to revoke the token for given user'), 400)
        #response.headers["Content-Type"] = "application/json"
        #return response
        flash('failed to revoke the token for given user')
        return redirect ('/index')

# Begin Helper Methods ---
def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

def getUserInfo(user_id):
    user = session.query(User).filter_by(id = user_id).one()
    return user

def getAssetID(asset_name):
    try:
        asset = session.query(Asset).filter_by(name = asset_name).first()
        return asset.id
    except:
        return None

def createUser(login_session):
    #Create a New User
    now = datetime.datetime.now()
    #format_now = now.strftime('%Y-%m-%d %H:%M:%S')
    newUser = User(name = login_session['username'], email = login_session['email'], picture = login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email = login_session['email']).one()
    #Create new asset asociated with the user
    name = "Asset_" + str(user.id)
    newAsset = Asset(name = name, activated = "true")
    session.add(newAsset)
    session.commit()
    asset = session.query(Asset).filter_by(name = name).first()
    print asset.name
    #Create asset owned by the user
    newOrderBook = OrderBook(type = "buy", ammount = 100000, user_id = user.id, asset_id = asset.id)
    session.add(newOrderBook)
    session.commit()
    return user.id
#--- End Helper Methods

@app.route('/')
@app.route('/index/')
def index():
    return render_template('index.html')

#New Order Book
@app.route('/newOrderbook/', methods=['GET','POST'])
def newOrderBook():
    print "#1 newOrderBook"
    #Begin User Validation ---->
    if 'username' not in login_session:
      return redirect ('/login')
    #check that the access token is valid
    #with this URL and the acces token appended. Verify this is a valid token.
    access_token = login_session['access_token']
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
    #With the following line Create a json with the result of the get request contanining the url  and the acess token.
    h = httplib2.Http()
    result = json.loads(h.request(url,'GET')[1])
    #if there was an error in the result because access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return redirect ('/gdisconnect')
    #Verify that access token is used for the intented user
    #Here the token is stored from credentials object and compare with the user_id by the google URL.
    if result['user_id'] != login_session['gplus_id']:
        response = make_response(
            json.dumps("token's user id doesn't match given user_id."), 401)
        response.headers['Content-Type'] = 'application/json'
        return redirect ('/gdisconnect')
    #----> End User Validation 

    print "#2 newOrderBook"
    user_id = login_session['user_id']
    creator = getUserInfo(user_id)
    print "#3 newOrderBook"
    if request.method == 'POST':
        print "#4 newOrderBook"
        asset_id = getAssetID(request.form['asset_name'])
        ammount = int(request.form['ammount'])
        if request.form['type'] == "buy":
            if asset_id is None:
                newAsset = Asset(name = request.form['asset_name'], activated = "true")
                session.add(newAsset)
                session.commit()
                asset_id = getAssetID(newAsset.name)
            newOrderBook = OrderBook(type = request.form['type'], ammount = ammount, user_id = user_id, asset_id = asset_id)
            session.add(newOrderBook)
            session.commit()
            flash('Nueva Orden de %s Successfully Created' % (newOrderBook.type))
            return redirect(url_for('orderBook'))
        elif request.form['type'] == "sell":
            ordersell = session.query(OrderBook).filter_by(asset_id = asset_id, user_id = user_id)
            if ordersell is None:
                flash('No Ha Adquirido el Activo: %s, No Puede Venderlo' % (request.form['asset_name']))
                return redirect(url_for('orderBook'))
            newOrderBook = OrderBook(type = request.form['type'], ammount = ammount, user_id = user_id, asset_id = asset_id)
            session.add(newOrderBook)
            session.commit()
            flash('Nueva Orden de %s Successfully Created' % (newOrderBook.type))
            return redirect(url_for('orderBook'))
    print "#4 newOrderBook"
    return render_template('newOrderBook.html', creator = creator)

#Order_Book
@app.route('/orderbook/')
def orderBook():
    #Begin User Validation ---->
    if 'username' not in login_session:
      return redirect ('/login')
    access_token = login_session['access_token']
    #check that the access token is valid
    #with this URL and the acces token appended. Verify this is a valid token.
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
    #With the following line Create a json with the result of the get request contanining the url  and the acess token.
    h = httplib2.Http()
    result = json.loads(h.request(url,'GET')[1])
    #if there was an error in the result because access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return redirect ('/gdisconnect')
    #Verify that access token is used for the intented user
    #Here the token is stored from credentials object and compare with the user_id by the google URL.
    if result['user_id'] != login_session['gplus_id']:
        response = make_response(
            json.dumps("token's user id doesn't match given user_id."), 401)
        response.headers['Content-Type'] = 'application/json'
        return redirect ('/gdisconnect')
    #----> End User Validation

    user_id = login_session['user_id']
    creator = getUserInfo(user_id)
 
    terms = ["type='buy'", "user_id=user_id"]
    buyorders = session.query(OrderBook).filter_by(user_id = user_id, type = "buy")
    terms = ["type='sell'", "user_id=user_id"]
    sellorders = session.query(OrderBook).filter_by(user_id = user_id, type = "sell")
    return render_template('orderbook.html', buyorders = buyorders, sellorders = sellorders, creator = creator)


if __name__ == '__main__':
  app.secret_key = 'super_secret_key'
  app.debug = True
  app.run(host = '0.0.0.0', port = 5000)
