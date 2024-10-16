# -*- coding: utf-8 -*-
#
# Supplemental class to handle concurrent logins by using the same tokens stored in HashiCorp Vault
#

import hvac
import os
import time

TOKEN_PATH = '/tmp/vault_token'
VAULT_PATH = 'automation_fmc_tokens'
VAULT_MOUNT = 'network'

class Vault:

    def __init__(self):
        if not os.path.exists(TOKEN_PATH):
            raise ValueError('No token file')
        # Authentication
        with open(TOKEN_PATH) as f:
            vault_info = f.read().splitlines()[-1].split(' ')

            self.client = hvac.Client(
                url=vault_info[0],
            )
            self.client.auth.approle.login(
                role_id=vault_info[1],
                secret_id=vault_info[2],
            )
            f.close()
        # os.remove(TOKEN_PATH)

    def get_tokens(self):
        # Reading a secret
        read_response = self.client.secrets.kv.v2.read_secret(
            path=VAULT_PATH,
            mount_point=VAULT_MOUNT,
            raise_on_deleted_version=False,
        )

        secrets = read_response['data']['data']
        if not self._is_token_valid(secrets):
            return None

        return secrets

    def update_tokens(self, access_token, refresh_tokens):
        try:
            self.client.secrets.kv.v2.patch(
                path=VAULT_PATH,
                mount_point=VAULT_MOUNT,
                secret={
                    'access_token': access_token,
                    'refresh_token': refresh_tokens,
                    'token_timestamp': round(time.time() * 1000),
                },
            )
        except Exception as e:
            print(f"Could not store token to Vault: {e}")

    def _is_token_valid(self, secrets):
        try:
            current_ms = round(time.time() * 1000)
            token_ms = int(secrets.get('token_timestamp', ''))
        except:
            return False

        if (current_ms-token_ms) < (60000 * 30):
            return True
        return False
