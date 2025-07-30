import requests
import logging
from typing import Dict, Any, Optional
from urllib.parse import urlencode

log = logging.getLogger(__name__)


class FeishuOAuth2:
    """
    Feishu OAuth2 provider implementation
    Compatible with OpenWebUI OAuth framework
    """

    NAME = 'feishu'

    # Feishu OAuth endpoints
    AUTHORIZE_URL = 'https://accounts.feishu.cn/open-apis/authen/v1/authorize'
    ACCESS_TOKEN_URL = 'https://open.feishu.cn/open-apis/authen/v2/oauth/token'
    USER_INFO_URL = 'https://open.feishu.cn/open-apis/authen/v1/user_info'

    def __init__(self, client_id: str, client_secret: str):
        self.client_id = client_id
        self.client_secret = client_secret

    def create_authorization_url(self, redirect_uri: str, state: Optional[str] = None) -> str:
        """Generate Feishu authorization URL"""
        params = {
            'app_id': self.client_id,
            'redirect_uri': redirect_uri,
            'scope': 'contact:user.base:readonly',
            'state': state or '',
            'response_type': 'code'
        }

        return f"{self.AUTHORIZE_URL}?{urlencode(params)}"

    def fetch_access_token(self, code: str, redirect_uri: str) -> Dict[str, Any]:
        """Exchange authorization code for access token"""
        data = {
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'redirect_uri': redirect_uri
        }

        try:
            response = requests.post(
                self.ACCESS_TOKEN_URL,
                json=data,
                headers={'Content-Type': 'application/json'},
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            log.error(f"Feishu token exchange failed: {str(e)}")
            raise Exception(f"Feishu token exchange failed: {str(e)}")

    def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get user information from Feishu"""
        try:
            response = requests.get(
                self.USER_INFO_URL,
                headers={'Authorization': f'Bearer {access_token}'},
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            log.error(f"Feishu user info request failed: {str(e)}")
            raise Exception(f"Feishu user info request failed: {str(e)}")

    def parse_user_data(self, user_info: Dict[str, Any]) -> Dict[str, str]:
        """Parse Feishu user data to OpenWebUI format"""
        data = user_info.get('data', {})
        log.debug(f'Feishu user data: {data}')
        return {
            'sub': data.get('user_id'),
            'email': data.get('email', '').lower(),
            'name': data.get('name', 'Feishu User'),
            'picture': data.get('avatar_url', '')
        }