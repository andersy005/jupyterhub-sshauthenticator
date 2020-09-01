from jupyterhub.auth import Authenticator
import fabric 
from tornado import gen
from traitlets import Int, Unicode 
import paramiko

class SSHAuthenticator(Authenticator):
    server_address = Unicode(
        config=True,
        help='Address of SSH server to contact'
    )
    server_port = Int(
        config=True,
        help='Port on which to contact SSH server.',
    )

    @gen.coroutine
    def authenticate(self, handler, data):
        username = data["username"]
        password = data["password"]

        session = fabric.Connection(self.server_address, user=username, connect_kwargs={'password': password})
        try:
            session.open()
            return data['username']
        except paramiko.AuthenticationException:
            return 






