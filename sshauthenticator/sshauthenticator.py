import os
from pathlib import Path

import fabric
import paramiko
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jupyterhub.auth import Authenticator
from traitlets import Int, Unicode


class SSHAuthenticator(Authenticator):
    server_address = Unicode(help='Address of SSH server to contact').tag(config=True)
    server_port = Int(
        help='Port on which to contact SSH server.',
    ).tag(config=True)
    identify_file_path = Unicode('/tmp/', help='The path for identity files').tag(config=True)

    async def authenticate(self, handler, data):
        username = data['username']
        password = data['password']

        session = fabric.Connection(
            self.server_address, user=username, connect_kwargs={'password': password}
        )
        try:
            session.open()
            key = rsa.generate_private_key(
                backend=default_backend(), public_exponent=65537, key_size=2048
            )
            private_key = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode('utf-8')
            public_key = (
                key.public_key()
                .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
                .decode('utf-8')
            )

            keys = [
                (public_key, Path(self.identify_file_path) / f'{username}_jhub.pub.key'),
                (private_key, Path(self.identify_file_path) / f'{username}_jhub.key'),
            ]
            self._write_keys(keys)
            session.run('mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys')
            session.put(keys[0][-1], '.ssh/')
            session.run(f'cat ~/.ssh/{keys[0][-1]} >> ~/.ssh/authorized_keys')
            return data['username']
        except paramiko.AuthenticationException:
            return

    def _write_keys(self, keys):
        for key, file_path in keys:
            with open(file_path, 'w') as f:
                f.write(key)
            os.chmod(file_path, 0o600)
