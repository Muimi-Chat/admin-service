import os
import json
import uuid
import traceback

from django.db import IntegrityError

from django.core.cache import cache
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from .services.validate_cloudflare_token import validate_cloudflare_token

from .enums.account_status import AccountStatus

from .enums.log_severity import LogSeverity

from .models import Account, CommonPasswords, ServiceLog, SessionToken

from .controllers import validate_session_token

from .utils.is_valid_password import is_valid_password

from .services.request_decrypt import request_decrypt
from .services.request_encrypt import request_encrypt
from .services.verify_totp_code import verify_totp_code
from .services.generate_email_verification_token import generate_email_verification_token
from .services.verify_email_verification_token import verify_email_verification_token
from .services.send_email_with_content import send_email_with_content

from argon2.exceptions import VerifyMismatchError
from argon2 import PasswordHasher

from .utils.verify_password import verify_password
from .utils.is_valid_password import is_valid_password
from .utils.is_valid_email import is_valid_email
from .utils.hash_password import hash_password
from .utils.hash_email import hash_email
from .utils.generate_password_reset_url import generate_password_reset_url

def _verify_csrf(csrf_token, user_agent, ip_address):
    """
    Helper function to verify the CSRF token against a User Agent.

    Returns None object, if the CSRF token is valid.
    Returns a JsonResponse object to be sent back to the client, if theres any bad CSRF

    Auto-logs into the database if there are any possible CSRF Attack.
    """
    if not user_agent:
        return JsonResponse({'ERROR': 'User agent is missing or empty'}, status=400)
    if not csrf_token:
        return JsonResponse({'ERROR': 'Missing CSRF Token'}, status=400)
    original_user_agent = cache.get(csrf_token)
    if original_user_agent is None:
        return JsonResponse({'ERROR': 'Expire CSRF Token'}, status=403)

    if original_user_agent != user_agent:
        # CSRF Token did not came from the same requestor client.
        log_message = f"Detected possible CSRF Attack on {csrf_token}, source from {ip_address} using {user_agent}; Original CSRF created by {original_user_agent}"
        print(log_message)
        try:
            log = ServiceLog.objects.create(
                content=log_message,
                severity=LogSeverity.ERROR
            )
            log.save()
        except Exception:
            print("Failed to log the CSRF Attack into database!")
        cache.delete(csrf_token)
        return JsonResponse({'ERROR': 'CSRF Attack!'}, status=403)
    return None

def _is_common_password(password: str):
    has_rows = CommonPasswords.objects.exists()
    if not has_rows:
        # Bulk populate top 100 thousand common passwords from Seclist...
        print('Populating common passwords from file...', flush=True)
        log = ServiceLog.objects.create(
            content='Populating common passwords from file...',
            severity=LogSeverity.LOG
        )
        log.save()

        passwords = []
        static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'static')
        file_path = os.path.join(static_dir, 'xato-net-10-million-passwords-100000.txt')
        with open(file_path, 'r') as file:
            for line in file:
                password_from_file = line.strip()
                if not password_from_file:
                    continue #empty line
                passwords.append(CommonPasswords(password=password_from_file))
        CommonPasswords.objects.bulk_create(passwords)

    is_common = CommonPasswords.objects.filter(password=password).exists()
    return is_common

@csrf_exempt
def send_forgot_password_email(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'ERROR'}, status=404)

    data = json.loads(request.body)
    username = data.get('username', '')

    cloudflare_token = data.get('cloudflare_token', '')
    ip_address = request.META.get('REMOTE_ADDR', '')
    csrf_token = request.headers.get('X-CSRFToken', '')
    user_agent = request.META['HTTP_USER_AGENT']
    csrf_status = _verify_csrf(csrf_token, user_agent, ip_address)
    if not csrf_status is None:
        return csrf_status
    if not validate_cloudflare_token(cloudflare_token, ip_address):
        return JsonResponse({'status': 'INVALID_CLOUDFLARE_TOKEN'}, status=403)

    account = Account.objects.filter(username=username).first()
    if account is None:
        return JsonResponse({'status': 'BAD_SESSION_TOKEN'}, status=401)
    
    if account.status != AccountStatus.OK:
        return JsonResponse({'status': 'ACCOUNT_DISABLED'}, status=401)
    
    has_request_reset_recently = cache.get(f"email_verification_{str(account.id)}")
    if has_request_reset_recently is not None:
        return JsonResponse({'status': 'WAIT_BEFORE_SENDING'}, status=403)
    
    email = request_decrypt(account.id, account.encrypted_email, account.id)

    try:
        # Generate password reset token
        response = generate_email_verification_token(str(account.id))
        if response['status'] != "SUCCESS":
            return JsonResponse({'status': 'ERROR'}, status=500)
        
        # Send email with reset URL
        verification_token = response['verificationToken']
        token_id = str(response['tokenID'])

        reset_url = generate_password_reset_url(token_id, verification_token)
        email_content = f"Heres your password reset URL: {reset_url}. This URL will expire in 1 hour. Ignore or contact admin if this wasn't you!"
        email_header = "Muimi Password Reset URL"
        response = send_email_with_content(email, email_header, email_content)
        if not response['success']:
            return JsonResponse({'status': 'ERROR'}, status=500)
        cache.set(f"email_verification_{str(account.id)}", True, timeout=360)

        log = ServiceLog.objects.create(
            content=f"{account.username} ({account.id}) has request a password reset!",
            severity=LogSeverity.VERBOSE
        )
        log.save()
    except Exception as e:
        log_message = f"Tried to reset password URL for {account.username} ({account.id}), but failed due to :: {e}\n\n{traceback.format_exc()}"
        print(log_message, flush=True)
        log = ServiceLog.objects.create(
            content=log_message,
            severity=LogSeverity.ERROR
        )
        log.save()
        return JsonResponse({'status': 'ERROR'}, status=500)
    
    cache.set(f"password_reset_{verification_token}", str(account.id), timeout=3610)
    return JsonResponse({'status': 'SUCCESS'}, status=200)

@csrf_exempt
def confirm_password_reset(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'ERROR'}, status=404)

    data = json.loads(request.body)

    user_agent = request.META['HTTP_USER_AGENT']

    # Check cloudflare/csrf
    cloudflare_token = data.get('cloudflare_token', '')
    ip_address = request.META.get('REMOTE_ADDR', '')
    csrf_token = request.headers.get('X-CSRFToken', '')
    user_agent = request.META['HTTP_USER_AGENT']
    csrf_status = _verify_csrf(csrf_token, user_agent, ip_address)
    if not csrf_status is None:
        return csrf_status
    if not validate_cloudflare_token(cloudflare_token, ip_address):
        return JsonResponse({'status': 'INVALID_CLOUDFLARE_TOKEN'}, status=403)
    
    token = data.get('token', '')
    tokenID = data.get('tokenID', '')

    # CHeck password valid or common
    new_password = data.get('newPassword', '')
    if not is_valid_password(new_password):
        return JsonResponse({'status': 'INVALID_PASSWORD'}, status=400)
    if _is_common_password(new_password):
        return JsonResponse({'status': 'COMMON_PASSWORD'}, status=400)

    print("verify reset", flush=True)
    # Check token/tokenID valid.
    try:
        result = verify_email_verification_token(tokenID, token)
        if not result['valid']:
            return JsonResponse({'status': 'INVALID_TOKEN'}, status=403)
    except Exception as e:
        print(e, flush=True)
        log = ServiceLog.objects.create(
            content=f"Failed to verify email change token due to :: {e}",
            severity=LogSeverity.ERROR
        )
        return JsonResponse({'status': 'INVALID_TOKEN'}, status=404)
    print("done request verify", flush=True)

    # Fetch account by from cached ID
    account_uuid = cache.get(f"password_reset_{token}")
    if account_uuid is None:
        return JsonResponse({'status': 'INVALID_TOKEN'}, status=400)
    print(f"cache get OK :: {account_uuid}", flush=True)

    if not account_uuid == result['accountID']:
        return JsonResponse({'status': 'INVALID_TOKEN'}, status=403)
    print(f"cache match OK", flush=True)

    # Check account status
    account = Account.objects.filter(id=uuid.UUID(account_uuid)).first()
    if account is None:
        return JsonResponse({'status': 'BAD_SESSION_TOKEN'}, status=401)
    if account.status != AccountStatus.OK:
        return JsonResponse({'status': 'ACCOUNT_DISABLED'}, status=401)
    
    # Update password
    hashed_password = hash_password(new_password)
    account.hashed_password = hashed_password
    account.authenticated = True
    account.save()

    SessionToken.objects.filter(account=account).delete()
    cache.delete(f"password_reset_{token}")

    try:
        email = request_decrypt(account.id, account.encrypted_email, account.id)
        send_email_with_content(email, 'Password Reset', 'This is a notice that you have reset your account password! All other account session will expire!')
    except Exception as e:
        print(e, flush=True)
        log = ServiceLog.objects.create(
            content=f"Failed to send password change notification to {account.username} ({account.id}) due to :: {e}",
            severity=LogSeverity.ERROR
        )
        log.save()

    log = ServiceLog.objects.create(
        content=f"{account.username} ({account.id}) has confirmed password reset!",
        severity=LogSeverity.LOG
    )
    log.save()
    return JsonResponse({'status': 'SUCCESS'}, status=200)