import os
import json
import uuid
import traceback

from django.db import IntegrityError

from django.core.cache import cache
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from .enums.account_status import AccountStatus

from .enums.access_attribute import AccessAttribute
from .enums.log_severity import LogSeverity

from .models import Account, ServiceLog, SessionToken, AccountAccess

from .controllers import validate_session_token

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
from .utils.generate_email_change_confirm_url import generate_email_change_confirm_url

@csrf_exempt
def request_user_info(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'ERROR'}, status=404)

    data = json.loads(request.body)
    session_token = request.headers.get('session-token', '')
    user_agent = request.META['HTTP_USER_AGENT']
    username = data.get('username', '')

    account = validate_session_token(username, user_agent, session_token)
    if account is None:
        return JsonResponse({'status': 'BAD_SESSION_TOKEN'}, status=401)
    
    email = request_decrypt(account.id, account.encrypted_email, account.id)
    user_data = {
        'username': account.username,
        'email': email,
        'totpEnabled': account.totp_enabled,
        'createdAt': account.created_at,
        'deactivated': account.status != AccountStatus.OK,
        'authenticated': account.authenticated
    }

    pepper_hex = os.environ.get('PEPPER_KEY', 'pepper-not-set')
    pepper_bytes = bytes.fromhex(pepper_hex)
    hasher = PasswordHasher()

    # Fetch all existing sessions and put to user.
    sessions = []
    sessions_ORM = SessionToken.objects.filter(account=account)
    for session in sessions_ORM:
        client_info = request_decrypt(account.id, session.encrypted_client_info, account.id)
        country = request_decrypt(account.id, session.encrypted_country, account.id)

        is_self_session = False
        try:
            hasher = PasswordHasher()
            if hasher.verify(session.hashed_token, session_token.encode() + pepper_bytes):
                if user_agent == client_info:
                    is_self_session = True
        except VerifyMismatchError:
            is_self_session = False

        sessions.append({
            'id': session.id,
            'clientInfo': client_info,
            'country': country,
            'createdAt': session.creation_date,
            'expiryDate': session.expiry_date,
            'isSelfSession': is_self_session
        })

    attributes_ORM = AccountAccess.objects.filter(account=account)
    attributes = []
    for attribute in attributes_ORM:
        attributes.append({
            'totpRequired': attribute.access_attribute >= 1,
            'access': AccessAttribute(attribute.access_attribute).name
        })

    return JsonResponse({
        'status': "SUCCESS",
        'userData': user_data,
        'sessions': sessions,
        'accessAttributes': attributes
    })

@csrf_exempt
def change_email(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'ERROR'}, status=404)

    data = json.loads(request.body)

    session_token = request.headers.get('session-token', '')
    user_agent = request.META['HTTP_USER_AGENT']
    password = data.get('password', '')
    username = data.get('username', '')
    new_email = data.get('new_email', '')
    totp_code = data.get('totp_code', '')

    account = validate_session_token(username, user_agent, session_token)
    if account is None:
        return JsonResponse({'status': 'BAD_SESSION_TOKEN'}, status=401)
    if not account.authenticated:
        return JsonResponse({'status': 'NOT_AUTHENTICATED'}, status=401)
    if account.status != AccountStatus.OK:
        return JsonResponse({'status': 'ACCOUNT_DISABLED'}, status=401)
    
    has_request_change_recently = cache.get(f"email_verification_{str(account.id)}")
    if has_request_change_recently is not None:
        return JsonResponse({'status': 'WAIT_BEFORE_SENDING'}, status=403)

    # Check TOTP if required
    if account.totp_enabled and not totp_code:
        return JsonResponse({'status': 'MISSING_TOTP'}, status=403)
    if account.totp_enabled:
        verify_result = verify_totp_code(account.id, totp_code)
        verify_status = verify_result['status']
        if verify_status != 'SUCCESS':
            return JsonResponse({'status': 'ERROR'}, status=500)
        if not verify_result['valid']:
            return JsonResponse({'status': 'BAD_TOTP'}, status=403)
        
    if not verify_password(account.hashed_password, password):
        return JsonResponse({'status': 'BAD_CURRENT_PASSWORD'}, status=403)
    
    if not is_valid_email(new_email):
        return JsonResponse({'status': 'INVALID_EMAIL'}, status=400)

    encrypted_email = request_encrypt(account.id, new_email, account.id)
    hashed_email = hash_email(new_email)

    try:
        # Generate email verification token
        response = generate_email_verification_token(str(account.id))
        if response['status'] != "SUCCESS":
            return JsonResponse({'status': 'ERROR'}, status=500)
        
        # Send email with verification URL
        verification_token = response['verificationToken']
        token_id = str(response['tokenID'])

        verification_url = generate_email_change_confirm_url(token_id, verification_token)
        email_content = f"Heres your email change confirmation URL: {verification_url}. This confirmation URL will expire in 1 hour."
        email_header = "Muimi Email Change Verification"
        response = send_email_with_content(new_email, email_header, email_content)
        if not response['success']:
            return JsonResponse({'status': 'ERROR'}, status=500)
        cache.set(f"email_verification_{str(account.id)}", True, timeout=360)

        log = ServiceLog.objects.create(
            content=f"{account.username} ({account.id}) has requested to change email to {new_email}",
            severity=LogSeverity.VERBOSE
        )
        log.save()
    except Exception as e:
        log_message = f"Tried to send new change confirmation email for {account.username} ({account.id}), but failed due to :: {e}\n\n{traceback.format_exc()}"
        print(log_message, flush=True)
        log = ServiceLog.objects.create(
            content=log_message,
            severity=LogSeverity.ERROR
        )
        log.save()
        return JsonResponse({'status': 'ERROR'}, status=500)
    
    cache.set(f"email_change_hash_{str(account.id)}", hashed_email, timeout=3615)
    cache.set(f"email_change_encrypted_{str(account.id)}", encrypted_email, timeout=3615)
    return JsonResponse({'status': 'SUCCESS'}, status=200)

@csrf_exempt
def confirm_email_change(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'ERROR'}, status=404)

    data = json.loads(request.body)

    session_token = request.headers.get('session-token', '')
    user_agent = request.META['HTTP_USER_AGENT']
    username = data.get('username', '')
    token = data.get('token', '')
    tokenID = data.get('tokenID', '')

    account = validate_session_token(username, user_agent, session_token)
    if account is None:
        return JsonResponse({'status': 'BAD_SESSION_TOKEN'}, status=401)
    
    if not account.authenticated:
        return JsonResponse({'status': 'NOT_AUTHENTICATED'}, status=401)
    if account.status != AccountStatus.OK:
        return JsonResponse({'status': 'ACCOUNT_DISABLED'}, status=401)
    
    try:
        result = verify_email_verification_token(tokenID, token)
        if not result['valid']:
            return JsonResponse({'status': 'INVALID_TOKEN'}, status=403)
        
        if not str(account.id) == result['accountID']:
            return JsonResponse({'status': 'INVALID_TOKEN'}, status=403)
    except Exception as e:
        print(e, flush=True)
        log = ServiceLog.objects.create(
            content=f"Failed to verify email change token due to :: {e}",
            severity=LogSeverity.ERROR
        )
        return JsonResponse({'status': 'INVALID_TOKEN'}, status=404)

    
    hashed_email = cache.get(f"email_change_hash_{str(account.id)}")
    encrypted_email = cache.get(f"email_change_encrypted_{str(account.id)}")

    if not hashed_email or not encrypted_email:
        return JsonResponse({'status': 'INVALID_TOKEN'}, status=401)

    old_encrypted_email = account.encrypted_email
    try:
        account.hashed_email = hashed_email
        account.encrypted_email = encrypted_email
        account.save()
    except IntegrityError as e:
        if 'hashed_email' in str(e):
            return JsonResponse({'status': 'EMAIL_TAKEN'}, status=409)

    try:
        email = request_decrypt(account.id, old_encrypted_email, account.id)
        send_email_with_content(email, 'Email Changed (Admin)', 'This is a notice that you have changed your email account for Muimi! If this is not intended, please reply to contact admin!')
    
        log = ServiceLog.objects.create(
            content=f"{account.username} ({account.id}) has confirmed email change!",
            severity=LogSeverity.LOG
        )
        log.save()
    except Exception as e:
        print(e, flush=True)
        log = ServiceLog.objects.create(
            content=f"Failed to send email change notification to {account.username} ({account.id}) due to :: {e}",
            severity=LogSeverity.ERROR
        )
        log.save()

    cache.delete(f"email_change_hash_{str(account.id)}")
    cache.delete(f"email_change_encrypted_{str(account.id)}")
    return JsonResponse({'status': 'SUCCESS'}, status=200)

@csrf_exempt
def change_password(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'ERROR'}, status=404)

    data = json.loads(request.body)

    session_token = request.headers.get('session-token', '')
    user_agent = request.META['HTTP_USER_AGENT']
    username = data.get('username', '')
    password = data.get('password', '')
    current_password = data.get('current_password', '')
    totp_code = data.get('totp_code', '')

    account = validate_session_token(username, user_agent, session_token)
    if account is None:
        return JsonResponse({'status': 'BAD_SESSION_TOKEN'}, status=401)
    
    if account.status != AccountStatus.OK:
        return JsonResponse({'status': 'ACCOUNT_DISABLED'}, status=401)

    # Check TOTP if required
    if account.totp_enabled and not totp_code:
        return JsonResponse({'status': 'MISSING_TOTP'}, status=403)
    if account.totp_enabled:
        verify_result = verify_totp_code(account.id, totp_code)
        verify_status = verify_result['status']
        if verify_status != 'SUCCESS':
            return JsonResponse({'status': 'ERROR'}, status=500)
        if not verify_result['valid']:
            return JsonResponse({'status': 'BAD_TOTP'}, status=403)
    
    # Check passwording
    if not verify_password(account.hashed_password, current_password):
        return JsonResponse({'status': 'BAD_CURRENT_PASSWORD'}, status=403)
    
    if not is_valid_password(password):
        return JsonResponse({'status': 'BAD_PASSWORD'}, status=400)
    
    hashed_password = hash_password(password)
    account.hashed_password = hashed_password
    account.authenticated = True
    account.save()

    SessionToken.objects.filter(account=account).delete()

    try:
        email = request_decrypt(account.id, account.encrypted_email, account.id)
        send_email_with_content(email, 'Password Changed (Admin)', 'This is a notice that you have just changed password! All other sessions will automatically expire!')
    except Exception as e:
        print(e, flush=True)
        log = ServiceLog.objects.create(
            content=f"Failed to send password change notification to {account.username} ({account.id}) due to :: {e}",
            severity=LogSeverity.ERROR
        )
        log.save()

    return JsonResponse({
        'status': 'SUCCESS'
    })

@csrf_exempt
def revoke_session(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'ERROR'}, status=404)

    data = json.loads(request.body)

    session_token = request.headers.get('session-token', '')
    user_agent = request.META['HTTP_USER_AGENT']
    username = data.get('username', '')
    session_id = data.get('session_id', '')

    account = validate_session_token(username, user_agent, session_token)
    if account is None:
        return JsonResponse({'status': 'BAD_SESSION_TOKEN'}, status=401)
    
    if not account.authenticated:
        return JsonResponse({'status': 'NOT_AUTHENTICATED'}, status=401)
    if account.status != AccountStatus.OK:
        return JsonResponse({'status': 'ACCOUNT_DISABLED'}, status=401)
    
    SessionToken.objects.filter(account=account, id=session_id).delete()

    log = ServiceLog.objects.create(
        content=f"{account.username} ({account.id}) removed a session token!",
        severity=LogSeverity.LOG
    )
    log.save()

    return JsonResponse({
        'status': 'SUCCESS'
    })