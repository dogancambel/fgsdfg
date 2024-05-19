import requests
import time
import base64
import hmac
import hashlib
from requests.exceptions import ProxyError, ConnectionError
import threading

def generate_totp(secret_key):
    time_interval = int(time.time() / 30)
    time_bytes = time_interval.to_bytes(8, 'big')
    secret_bytes = base64.b32decode(secret_key, casefold=True)
    hmac_hash = hmac.new(secret_bytes, time_bytes, hashlib.sha1).digest()
    offset = hmac_hash[-1] & 0x0F
    code = (int.from_bytes(hmac_hash[offset:offset + 4], 'big') & 0x7FFFFFFF) % 1000000
    return f"{code:06}"

class Set2FA:
    def __init__(self, auth_token, x_csrf_token, proxy):
        self.base_url = "https://api.twitter.com/1.1/onboarding/task.json"
        self.proxies = {'https': proxy}
        self.headers = {
            "Authorization": "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA",
            "Content-Type": "application/json",
            "Cookie": f"auth_token={auth_token}; ct0={x_csrf_token};",
            "X-Csrf-Token": x_csrf_token,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.90 Safari/537.36"
        }
        self.flow_token = None

    def start_two_factor_auth(self):
        data = {
            "input_flow_data": {
                "flow_context": {
                    "debug_overrides": {},
                    "start_location": {
                        "location": "manual_link",
                        "task_name": "two_factor_authentication"
                    }
                }
            },
            "subtask_versions": {
                "action_list": 2,
                "alert_dialog": 1,
                "app_download_cta": 1,
                "check_logged_in_account": 1,
                "choice_selection": 3,
                "contacts_live_sync_permission_prompt": 0,
                "cta": 7,
                "email_verification": 2,
                "end_flow": 1,
                "enter_date": 1,
                "enter_password": 5,
                "enter_pin": 4,
                "generic_urt": 3,
                "in_app_notification": 1,
                "interest_picker": 3,
                "js_instrumentation": 1,
                "menu_dialog": 1,
                "notification_settings": 6,
                "open_account": 2,
                "open_home_timeline": 1,
                "open_link": 1,
                "phone_verification": 4,
                "privacy_options": 1,
                "security_key": 3,
                "select_avatar": 4,
                "select_banner": 2,
                "settings_list": 7,
                "show_code": 1,
                "sign_up": 7,
                "sign_up_review": 4,
                "tweet_selection_urt": 1,
                "update_users": 1,
                "upload_media": 1,
                "user_recommendations_urt": 1,
                "user_recommendations_urt_large": 1,
                "user_recommendations_urt_medium": 1,
                "user_recommendations_urt_small": 1,
                "wait_spinner": 3,
                "web_modal": 1
            }
        }
        response = self._send_http_request(data)
        if 'flow_token' in response:
            self.flow_token = response['flow_token']
        return response

    def next_link(self):
        data = {
            "flow_token": self.flow_token,
            "subtask_inputs": [
                {
                    "subtask_id": "TwoFactorEnrollmentAuthenticationAppBeginSubtask",
                    "action_list": {"link": "next_link"}
                }
            ]
        }
        response = self._send_http_request(data)
        if 'flow_token' in response:
            self.flow_token = response['flow_token']
        return response

    def verify_password(self, password):
        data = {
            "flow_token": self.flow_token,
            "subtask_inputs": [
                {
                    "subtask_id": "TwoFactorEnrollmentVerifyPasswordSubtask",
                    "settings_list": [
                        {"setting": {"key": "password", "value": password}}
                    ]
                }
            ]
        }
        response = self._send_http_request(data)
        if 'flow_token' in response:
            self.flow_token = response['flow_token']
        return response

    def input_otp(self, otp):
        data = {
            "flow_token": self.flow_token,
            "subtask_inputs": [
                {
                    "subtask_id": "TwoFactorEnrollmentInputTextSubtask",
                    "enter_text": {"text": otp}
                }
            ]
        }
        response = self._send_http_request(data)
        if 'flow_token' in response:
            self.flow_token = response['flow_token']
        return response

    def complete_two_factor_auth(self):
        data = {"flow_token":self.flow_token,"subtask_inputs":[{"subtask_id":"TwoFactorEnrollmentAuthenticationAppCompleteSubtask","cta":{"link":"finish_link"}}]}
        response = self._send_http_request(data)
        return response
    
    def _send_http_request(self, data, query_string="", max_retries=10):
        response = None  # Varsayılan olarak None değeri atanır
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    f"{self.base_url}?{query_string}",
                    headers=self.headers,
                    json=data,
                    proxies=self.proxies,
                    timeout=10
                )
                response.raise_for_status()  # Hata kodlarına karşı kontrol yapar
                return response.json()
            except (ProxyError, ConnectionError) as e:
                print(f"Proxy hatası: {e}. Tekrar deneme {attempt + 1}/{max_retries}")
                # Proxy hatalarını yeniden deneme süresi ekleyebilirsiniz
                if attempt < max_retries - 1:
                    continue
                else:
                    raise  # Max deneme sayısına ulaşıldığında hata fırlat
            except Exception as e:
                print(f"Beklenmeyen bir hata oluştu: {e}")
                return response.json()  # Burada response değeri kullanılabilir
        return None  # Max deneme sayısına ulaştıktan sonra None dön

lock = threading.Lock()

def perform_two_factor_auth(line):
    username, password, email, x_csrf_token, auth_token = line.strip().split(':')
    with open('proxy.txt', 'r') as p:
        proxy_data = p.readline().strip()
    proxy = f"https://{proxy_data}"
    two_fa = Set2FA(auth_token, x_csrf_token, proxy)
    start_response = two_fa.start_two_factor_auth()
