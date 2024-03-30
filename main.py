# CITATION: Code adapted from base code provided at: https://canvas.oregonstate.edu/courses/1933801/assignments/9359495?module_item_id=2352 and throughout cs493 modules
# CITATION: auth0 python code based on code found at: https://auth0.com/docs/quickstart/webapp/python#setup-your-routes

from urllib.parse import quote_plus
from six.moves.urllib.parse import urlencode
from authlib.integrations.flask_client import OAuth
from flask import url_for
from flask import session
from flask import render_template
from flask import redirect
from flask import jsonify
from flask import Flask
from dotenv import load_dotenv, find_dotenv
from werkzeug.exceptions import HTTPException
from os import environ as env
from jose import jwt
from flask_cors import cross_origin
from six.moves.urllib.request import urlopen
import json
from functools import wraps
from google.cloud import datastore
from flask import Flask, request, jsonify, _request_ctx_stack, make_response
import requests
import os
from dotenv import load_dotenv


app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

BOATS = "boats"
LOADS = "loads"
OWNERS = "owners"

# Get sensitive info from private env file
load_dotenv()
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
DOMAIN = os.getenv('DOMAIN')

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
    server_metadata_url=f'https://{DOMAIN}/.well-known/openid-configuration'
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header


def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        return False

    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        return False
    if unverified_header["alg"] == "HS256":
        return False
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN + "/"
            )
        except jwt.ExpiredSignatureError:
            return False
        except jwt.JWTClaimsError:
            return False
        except Exception:
            return False

        return payload
    else:
        return False


# citation: from auth0 python walkthrough: https://auth0.com/docs/quickstart/webapp/python#setup-your-routes

@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True))


@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    return redirect("/")


@app.route("/logout")
def logout():
    session.clear()
    # error. redirect to home
    return redirect('/')


@app.route("/")
def home():
    if session:
        # use session sub to keep track of owners in data store
        sub = session['user']['userinfo']['sub']
        email = session['user']['userinfo']['email']

        # then, get all owners
        query = client.query(kind=OWNERS)
        allOwners = list(query.fetch())

        # from this, get all owners that are in data store. optimize with filter if have time
        allOwnerSubs = []

        # loop through all owners and gets subs
        # if sub not in list, add user to data store
        for owner in allOwners:
            allOwnerSubs.append(owner['sub'])

        if sub not in allOwnerSubs:
            # create a new user entity
            new_owner = datastore.entity.Entity(key=client.key(OWNERS))
            new_owner.update({"sub": sub, 'email': email})
            client.put(new_owner)
        # and then render home
        return render_template("home.html", session=session.get('user'), pretty=json.dumps(session.get('user'), indent=4))
    else:
        # else, just render home page
        return render_template("home.html", session=session.get('user'), pretty=json.dumps(session.get('user'), indent=4))


# citation: from auth0 python walkthrough: https://auth0.com/docs/quickstart/webapp/python#setup-your-routes

# general way of checking that user is logged in with valid JWT:
#   payload = verify_jwt(request) # this will return either False or with the payload
#   if payload:
#       do stuff
#   else:
#       return makeResponse(401) # unauthorized error

# Create a boat if the Authorization header contains a valid JWT

# boat-specific routes
# /boats for accessing collection of all boats or creating new ones
# /boats/<lid> for accessing/modifying specific boat


@app.route('/boats', methods=['POST', 'GET'])
def boats_routes():
    payload = verify_jwt(request)
    # only post and get make sense for this endpoint. otherwise, you need
    if request.method == 'POST':
        # if accept header is missing or it is present and does not include json or a wildcard
        if not request.headers.get('Accept') or request.headers.get('Accept') and 'application/json' not in request.headers.get('Accept') and '*/*' not in request.headers.get('Accept'):
            return makeResponse(406)
        payload = verify_jwt(request)
        if payload:
            ownerSub = payload['sub']
            content = request.get_json()
            new_boat = datastore.entity.Entity(key=client.key(BOATS))
            new_boat.update({"name": content["name"], "type": content["type"],
                            "length": content["length"], "public": content['public'], "owner": ownerSub, 'loads': []})
            client.put(new_boat)
            # now that boat has id, can generate
            selfURL = str(request.url) + '/' + str(new_boat.key.id)
            new_boat.update({'self': selfURL})
            client.put(new_boat)
            new_boat.update({'id': new_boat.key.id})
            return makeResponse(201, new_boat)
        else:
            return makeResponse(401)
    elif request.method == 'GET':
        # boats are now protected entities.
        # just return boats that belong to current user. If no JWT, return 401
        payload = verify_jwt(request)
        if payload:
            totalItems = 0  # counts how many items are returned
            query = client.query(kind=BOATS)
            query.add_filter('owner', '=', payload['sub'])
            ownersBoats = query.fetch()
            for boat in ownersBoats:
                totalItems += 1
            query = client.query(kind=BOATS)
            # add filter to just get boats that belong to owner
            query.add_filter('owner', '=', payload['sub'])
            # the rest of the code should be the same
            q_limit = int(request.args.get('limit', '5'))
            q_offset = int(request.args.get('offset', '0'))
            l_iterator = query.fetch(limit=q_limit, offset=q_offset)
            pages = l_iterator.pages
            results = list(next(pages))
            if l_iterator.next_page_token:
                next_offset = q_offset + q_limit
                next_url = request.base_url + "?limit=" + \
                    str(q_limit) + "&offset=" + str(next_offset)
            else:
                next_url = None
            for e in results:
                e["id"] = e.key.id
            output = {'total items:': totalItems, "boats": results}
            if next_url:
                output["next"] = next_url
            return makeResponse(200, json.dumps(output))
        else:
            return makeResponse(401)
    else:
        return makeResponse(405)


@ app.route('/boats/<bid>', methods=['GET', 'PUT', 'PATCH', 'DELETE'])
def delete_boat_by_id(bid):
    payload = verify_jwt(request)
    if request.method == 'GET':
        if payload:
            boat_key = client.key(BOATS, int(bid))
            boatToReturn = client.get(key=boat_key)
            if boatToReturn:
                if boatToReturn['owner'] == payload['sub']:
                    boatToReturn['id'] = boatToReturn.key.id
                    return makeResponse(200, boatToReturn)
                else:
                    return makeResponse(403)
            else:
                return makeResponse(404)
        else:
            return makeResponse(401)
    elif request.method == 'PUT':
        # if accept header is missing or it is present and does not include json or a wildcard
        if not request.headers.get('Accept') or request.headers.get('Accept') and 'application/json' not in request.headers.get('Accept') and '*/*' not in request.headers.get('Accept'):
            return makeResponse(406)
        if payload:
            ownerSub = payload['sub']
            content = request.get_json()
            boat_key = client.key(BOATS, int(bid))
            boat = client.get(key=boat_key)
            # for boats in db, if sub == that owner, add to return object, then return object
            if boat:
                if boat['owner'] == ownerSub:
                    # update boat here
                    boat.update({"name": content["name"], "type": content["type"],
                                 "length": content["length"], "public": content['public']})
                    client.put(boat)
                    boat['id'] = boat.key.id
                    # boat found. user is owner of boat. return boat
                    return makeResponse(200, boat)
                else:
                    # boat found. user is NOT owner of boat. return 403 forbidden
                    return makeResponse(403)
            # boat was not found. return 404 not found
            return makeResponse(404)
        # user is not authorized to search for boats. return 401
        else:
            return makeResponse(401)
    elif request.method == 'PATCH':
        # if accept header is missing or it is present and does not include json or a wildcard
        if not request.headers.get('Accept') or request.headers.get('Accept') and 'application/json' not in request.headers.get('Accept') and '*/*' not in request.headers.get('Accept'):
            return makeResponse(406)
        if payload:
            ownerSub = payload['sub']
            content = request.get_json()
            boat_key = client.key(BOATS, int(bid))
            boat = client.get(key=boat_key)
            # for boats in db, if sub == that owner, add to return object, then return object
            if boat:
                if boat['owner'] == ownerSub:
                    # update boat here. don't know which values will be updated, so loop thru and update per value. do not have to worry about data validation, so no checks required
                    attributeKeys = content.keys()
                    for key in attributeKeys:
                        boat.update({str(key): content[str(key)]})
                        client.put(boat)
                    boat['id'] = boat.key.id
                    # boat found. user is owner of boat. boat updated. return updated boat
                    return makeResponse(200, boat)
                else:
                    # boat found. user is NOT owner of boat. return 403 forbidden
                    return makeResponse(403)
            # boat was not found. return 404 not found
            return makeResponse(404)
        # user is not authorized to search for boats. return 401
        else:
            return makeResponse(401)
    elif request.method == 'DELETE':
        if payload:
            boat_key = client.key(BOATS, int(bid))
            boatToDelete = client.get(key=boat_key)
            if boatToDelete:
                if boatToDelete['owner'] == payload['sub']:
                    # loop through all loads on boat and set carrier to None
                    for load in boatToDelete['loads']:
                        lid = load['id']
                        load_key = client.key(LOADS, lid)
                        load = client.get(key=load_key)
                        load.update({'carrier': None})
                        client.put(load)
                    # now that loads are handled, delete boat
                    client.delete(boatToDelete.key)
                    return makeResponse(204)
                else:
                    # boat exist but user is not its owner
                    return makeResponse(403)
            else:
                return makeResponse(404)  # boat not found!
        else:
            # jwt invalid/missing
            return makeResponse(401)
    else:
        return makeResponse(405)
        # return jsonify(error='Method not recogonized')

# load-specific routes
# /loads for accessing collection of all loads or creating new ones
# /loads/<lid> for accessing/modifying specific load


@app.route('/loads', methods=['POST', 'GET'])
# loads not protected entity (not owned directly), so just return all regardless of jwt
def loads_routes():
    if request.method == 'POST':
        # if accept header is missing or it is present and does not include json or a wildcard
        if not request.headers.get('Accept') or request.headers.get('Accept') and 'application/json' not in request.headers.get('Accept') and '*/*' not in request.headers.get('Accept'):
            return makeResponse(406)
        content = request.get_json()
        new_load = datastore.entity.Entity(key=client.key(LOADS))
        new_load.update(
            {'carrier': None, 'weight': content['weight'], 'description': content['description'], 'date_created': content['date_created']})
        client.put(new_load)
        # now that it has an id, can generate self. update
        selfURL = str(request.url) + '/' + str(new_load.key.id)
        new_load.update({'self': selfURL})
        client.put(new_load)
        # you don't want to actually store the id of the boat in the boat entity, so just add it when the entity is returned
        new_load.update({'id': new_load.key.id})
        return makeResponse(201, new_load)
    elif request.method == 'GET':
        totalItems = 0  # counts how many items are returned
        query = client.query(kind=LOADS)
        allLoads = query.fetch()
        for load in allLoads:
            totalItems += 1
        query = client.query(kind=LOADS)
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        l_iterator = query.fetch(limit=q_limit, offset=q_offset)
        pages = l_iterator.pages
        results = list(next(pages))
        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + \
                str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None
        for e in results:
            e["id"] = e.key.id
        output = {'total items': totalItems, "loads": results}
        if next_url:
            output["next"] = next_url
        return makeResponse(200, json.dumps(output))
    else:
        return makeResponse(405)


@ app.route('/loads/<lid>', methods=['GET', 'PATCH', 'PUT', 'DELETE'])
def specific_load(lid):
    payload = verify_jwt(request)
    lid = int(lid)
    query = client.query(kind=LOADS)
    allLoads = list(query.fetch())
    if request.method == 'GET':
        for load in allLoads:
            if load.key.id == lid:
                returnLoad = {'id': load.key.id, 'carrier': load['carrier'], 'date_created': load['date_created'],
                              'description': load['description'], 'self': load['self'], 'weight': load['weight']}
                return makeResponse(200, returnLoad)
        return makeResponse(404)  # boat not found. return 404
    elif request.method == 'PATCH':
        # if accept header is missing or it is present and does not include json or a wildcard
        if not request.headers.get('Accept') or request.headers.get('Accept') and 'application/json' not in request.headers.get('Accept') and '*/*' not in request.headers.get('Accept'):
            return makeResponse(406)
        content = request.get_json()
        # from this, get all boats that belong to sub
        returnLoad = None
        # for boats in db, if sub == that owner, add to return object, then return object
        for load in allLoads:
            if load.key.id == lid:
                # update boat here. don't know which values will be updated, so loop thru and update per value. do not have to worry about data validation, so no checks required
                attributeKeys = content.keys()
                for key in attributeKeys:
                    load.update({str(key): content[str(key)]})
                    client.put(load)
                returnLoad = {'id': load.key.id, 'carrier': load['carrier'], 'date_created': load['date_created'],
                              'description': load['description'], 'self': load['self'], 'weight': load['weight']}
                # load found and updated. return load
                return makeResponse(200, returnLoad)
        # load was not found. return 404 not found
        return makeResponse(404)
    elif request.method == 'PUT':
        # if accept header is missing or it is present and does not include json or a wildcard
        if not request.headers.get('Accept') or request.headers.get('Accept') and 'application/json' not in request.headers.get('Accept') and '*/*' not in request.headers.get('Accept'):
            return makeResponse(406)
        content = request.get_json()
        query = client.query(kind=LOADS)
        allLoads = list(query.fetch())
        for load in allLoads:
            if load.key.id == lid:
                # update load here
                load.update({"weight": content["weight"], "description": content["description"],
                             "date_created": content["date_created"]})
                client.put(load)
                returnLoad = {"weight": content["weight"], "description": content["description"],
                              "date_created": content["date_created"], 'id': load.key.id, 'self': load['self'], 'carrier': load['carrier']}
                # load found. return load
                return makeResponse(200, returnLoad)
        # load was not found. return 404 not found
        return makeResponse(404)
    elif request.method == 'DELETE':
        # check if load is on a boat. if it is, changing it would affect boat, so it is considered protected
        # if not, then it is unprotected and you do not have to have a jwt to delete it
        load_key = client.key(LOADS, lid)
        load = client.get(key=load_key)
        if load:
            # if the load is on a boat, a valid and matching jwt is required
            # to delete the load
            if load['carrier']:
                # load has a carrier. next need to check req has a payload
                if payload:
                    # req has payload. check if jwt matches
                    carrier_key = client.key(BOATS, load['carrier']['id'])
                    carrier = client.get(key=carrier_key)
                    # check if carrier owner and payload sub match
                    if carrier['owner'] == payload['sub']:
                        for load in carrier['loads']:
                            if load['id'] == lid:
                                carrier['loads'].remove(load)
                                client.put(carrier)
                        # load has been removed from boat. now delete load from data store
                        client.delete(load_key)
                        return makeResponse(204)
                    else:
                        return makeResponse(403)
                else:
                    return makeResponse(401)
            else:
                # if not on a boat, it is fair game to be deleted w/o jwt
                client.delete(load.key)
                return makeResponse(204)
        else:
            return makeResponse(404)
    else:
        return makeResponse(405)


# route for adding or removing boat from load
# protected, because it involves changing the status of a boat

@ app.route('/boats/<bid>/<lid>', methods=['POST', 'DELETE'])
# route responsible for adding/removing loads to/from boats
# this route is considered protected because it affects boats
def relate_boat_and_load(bid, lid):
    bid = int(bid)
    lid = int(lid)
    payload = verify_jwt(request)
    if request.method == 'POST':
        # if accept header is missing or it is present and does not include json or a wildcard
        if not request.headers.get('Accept') or request.headers.get('Accept') and 'application/json' not in request.headers.get('Accept') and '*/*' not in request.headers.get('Accept'):
            return makeResponse(406)
        if payload:
            boat_key = client.key(BOATS, bid)
            boat = client.get(key=boat_key)
            load_key = client.key(LOADS, lid)
            load = client.get(key=load_key)
            # add the load to the boat
            if boat and load:  # if both exist
                if load['carrier']:  # if load is already on a boat
                    # return ({"Error": "The load is already loaded on another boat"}, 403)
                    return makeResponse(403)
                else:  # load does not have carrier
                    # is user authorized to make changes to boat?
                    if payload['sub'] == boat['owner']:
                        if 'loads' in boat.keys():  # if this already has loads, append the new one
                            # boat['loads'].append({load.id, load['self']})
                            boat['loads'].append(
                                {'id': lid, 'self': load['self']})
                        else:  # otherwise, add it as first
                            boat['loads'] = [{'id': lid, 'self': load['self']}]
                        client.put(boat)
                        # update load's carrier
                        load.update(
                            {"carrier": {'id': bid, 'self': boat['self']}})
                        client.put(load)
                        boat.update({'id': boat.key.id})
                        return makeResponse(200, boat)
                    else:
                        return makeResponse(403)
            else:
                return makeResponse(404)
        else:
            return makeResponse(401)
    elif request.method == 'DELETE':
        if payload:
            boat_key = client.key(BOATS, int(bid))
            boat = client.get(key=boat_key)
            load_key = client.key(LOADS, int(lid))
            load = client.get(key=load_key)
            # boat exists, but user is not its owner
            if boat:
                if boat['owner'] != payload['sub']:
                    return makeResponse(403)
            if boat and load:  # if both exist
                if 'loads' in boat.keys():
                    # roll thru all loads. if found, remove
                    for loadOnBoat in boat['loads']:
                        if loadOnBoat['id'] == lid:
                            boat['loads'].remove(loadOnBoat)
                            client.put(boat)
                            # remember that loadOnBoat is the thing the boat entity,
                            # but you want to update the load entity in the database
                            load.update({"carrier": None})
                            client.put(load)
                            # return ('', 204)
                            return makeResponse(204)
                    # boat has loads, but not this load. return error
                    return makeResponse(404)
                # boat has no loads. return error
                else:
                    return makeResponse(404)
            else:
                return makeResponse(404)
        else:
            return makeResponse(401)
    else:
        return makeResponse(405)


@ app.route('/users', methods=['GET'])
# this route is unprotected, so no verifying payload.
def get_users():
    if request.method == 'GET':
        query = client.query(kind=OWNERS)
        allOwners = list(query.fetch())
        ownersReturn = []
        for owner in allOwners:
            ownerItem = {'sub': owner['sub'],
                         'email': owner['email'], 'id': owner.key.id}
            ownersReturn.append(ownerItem)
        return makeResponse(200, ownersReturn)
    else:
        return makeResponse(405)


# method to standardize all messaging back to user
def makeResponse(code, message=None):
    res = make_response()
    if not message:
        if code == 200:
            res = make_response([])
    else:
        res = make_response(message)
    res.mimetype = 'application/json'
    res.status_code = code
    return res


@ app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload


# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@ app.route('/login', methods=['POST'])
def login_user():
    content = request.get_json()
    username = content["username"]
    password = content["password"]
    body = {'grant_type': 'password', 'username': username,
            'password': password,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
            }
    headers = {'content-type': 'application/json'}
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    return r.text, 200, {'Content-Type': 'application/json'}


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
