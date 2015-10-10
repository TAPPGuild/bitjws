# Install requirements: pip install flask flask-login
import flask
from flask.ext import login
import bitjws

# Server key used to sign responses. The client can optionally
# check that the response was signed by a key it knows to belong
# to this server.
privkey = bitjws.PrivateKey()
print("Server WIF key: {}".format(bitjws.privkey_to_wif(privkey.private_key)))
print("Server key address: {}".format(
    bitjws.pubkey_to_addr(privkey.pubkey.serialize())))

# Setup flask app with flask-login.
app = flask.Flask(__name__)
login_manager = login.LoginManager()
login_manager.init_app(app)

# Dummy User.
class User(login.UserMixin):
    def __init__(self, address):
        self.id = address

# Custom request authentication based on bitjws.
@login_manager.request_loader
def load_user_from_request(request):
    header, payload = bitjws.validate_deserialize(request.data.decode('utf8'))
    if header is None:
        # Validation failed.
        return None

    # Store the decoded payload so it can be used for processing the request.
    flask.g.payload = payload

    # In this example, Users are not loaded from a database or similar
    # and are always assumed to exist.
    return User(header['kid'])

# Example route that requires authentication. It returns the address used
# to sign the initial request as well a custom echo param.
@app.route('/', methods=['POST'])
@login.login_required
def echo():
    msg = flask.g.payload.get('echo', '')
    address = login.current_user.id
    response = bitjws.sign_serialize(privkey, address=address, echo=msg)
    return response

# Start a http server.
app.run(port=8001)
