import os
import json
import uuid
import traceback

from django.core.cache import cache
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from .enums.account_status import AccountStatus

from .enums.log_severity import LogSeverity

from .models import Account, ServiceLog

from .controllers import validate_session_token

from .services.validate_cloudflare_token import validate_cloudflare_token
from .services.generate_totp_token import generate_totp_token
from .services.verify_totp_code import verify_totp_code
from .services.generate_recovery_codes import generate_recovery_codes
from .services.verify_recovery_code import verify_recovery_code
from .services.send_email_with_content import send_email_with_content
from .services.request_decrypt import request_decrypt

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

@csrf_exempt
def enable_totp(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'ERROR'}, status=404)

    data = json.loads(request.body)

    session_token = request.headers.get('session-token', '')
    user_agent = request.META['HTTP_USER_AGENT']
    username = data.get('username', '')

    account = validate_session_token(username, user_agent, session_token)
    if account is None:
        return JsonResponse({'status': 'BAD_SESSION_TOKEN'}, status=401)
    if not account.authenticated:
        return JsonResponse({'status': 'NOT_AUTHENTICATED'}, status=401)
    if account.status != AccountStatus.OK:
        return JsonResponse({'status': 'ACCOUNT_DISABLED'}, status=401)
    
    if account.totp_enabled:
        return JsonResponse({'status': 'ALREADY_ENABLED'}, status=403)
    
    print('Generating TOTP secret...')
    response_data = generate_totp_token(account.id, account.username)
    print('Done TOTP secret...')
    if response_data['status'] != 'SUCCESS':
        return JsonResponse({'status': 'ERROR'}, status=500)
    
    log = ServiceLog.objects.create(
        content=f"{account.username} ({account.id}) has requested for TOTP",
        severity=LogSeverity.VERBOSE
    )
    log.save()

    return JsonResponse({
        'status': 'SUCCESS',
        'secret': response_data['secret'],
        'qrCodeUri': response_data['qrCodeUri']
    })

@csrf_exempt
def confirm_totp(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'ERROR'}, status=404)

    data = json.loads(request.body)

    session_token = request.headers.get('session-token', '')
    user_agent = request.META['HTTP_USER_AGENT']
    username = data.get('username', '')
    code = data.get('code', '')

    account = validate_session_token(username, user_agent, session_token)
    if account is None:
        return JsonResponse({'status': 'BAD_SESSION_TOKEN'}, status=401)
    if not account.authenticated:
        return JsonResponse({'status': 'NOT_AUTHENTICATED'}, status=401)
    if account.status != AccountStatus.OK:
        return JsonResponse({'status': 'ACCOUNT_DISABLED'}, status=401)
    
    if account.totp_enabled:
        return JsonResponse({'status': 'ALREADY_ENABLED'}, status=403)
    
    verify_result = verify_totp_code(account.id, code)
    if verify_result['status'] != 'SUCCESS':
        return JsonResponse({'status': 'ERROR'}, status=500)
    
    if not verify_result['valid']:
        return JsonResponse({'status': 'INVALID_CODE'}, status=403)
    
    recovery_codes_result = generate_recovery_codes(account.id)
    if recovery_codes_result['status'] != 'SUCCESS':
        return JsonResponse({'status': 'ERROR'}, status=500)
    
    codes = recovery_codes_result['codes']
    
    account.totp_enabled = True
    account.save()

    try:
        email = request_decrypt(account.id, account.encrypted_email, account.id)
        send_email_with_content(email, 'TOTP Enabled (Admin)', 'This is a notice that you have enabled TOTP on your account!')

        log = ServiceLog.objects.create(
            content=f"{account.username} ({account.id}) has confirmed TOTP",
            severity=LogSeverity.LOG
        )
        log.save()
    except Exception as e:
        print(e, flush=True)
        log = ServiceLog.objects.create(
            content=f"Failed to send TOTP disabled email to {account.username} ({account.id}) due to :: {e}",
            severity=LogSeverity.ERROR
        )
        log.save()

    return JsonResponse({'status': 'SUCCESS', 'codes': codes})

@csrf_exempt
def disable_totp(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'ERROR'}, status=404)

    data = json.loads(request.body)

    ip_address = request.META.get('REMOTE_ADDR', '')
    cloudflare_token = data.get('cloudflare_token', '')
    username = data.get('username', '')
    recovery_code = data.get('recovery_code', '')
    csrf_token = request.headers.get('X-CSRFToken', '')
    user_agent = request.META['HTTP_USER_AGENT']
    csrf_status = _verify_csrf(csrf_token, user_agent, ip_address)
    if not csrf_status is None:
        return csrf_status
    
    if not validate_cloudflare_token(cloudflare_token, ip_address):
        return JsonResponse({'status': 'INVALID_CLOUDFLARE_TOKEN'}, status=403)
    
    account = Account.objects.filter(username=username).first()
    if account is None:
        return JsonResponse({'status': 'BAD_USERNAME'}, status=403)
    if not account.authenticated:
        return JsonResponse({'status': 'NOT_AUTHENTICATED'}, status=401)
    if account.status != AccountStatus.OK:
        return JsonResponse({'status': 'ACCOUNT_DISABLED'}, status=401)
    
    account_tries = cache.get(f"disable_totp_tries_{str(account.id)}")
    if account_tries is None:
        account_tries = 0

    if int(account_tries) >= 5:
        return JsonResponse({'status': 'TOO_MANY_TRIES'}, status=403)
        
    
    if not account.totp_enabled:
        return JsonResponse({'status': 'ALREADY_DISABLED'}, status=403)
    
    cache.set(f"disable_totp_tries_{str(account.id)}", account_tries + 1, timeout=360)
    verify_result = verify_recovery_code(account.id, recovery_code)
    if verify_result['status'] != 'SUCCESS':
        return JsonResponse({'status': 'ERROR'}, status=500)
    
    if not verify_result['valid']:
        return JsonResponse({'status': 'INVALID_CODE'}, status=403)
    
    account.totp_enabled = False
    account.save()

    try:
        email = request_decrypt(account.id, account.encrypted_email, account.id)
        send_email_with_content(email, 'TOTP Disabled Successfully (Admin)', 'This is a notice that you have disabled TOTP successfully!')

        log = ServiceLog.objects.create(
            content=f"{account.username} ({account.id}) has disabled TOTP",
            severity=LogSeverity.LOG
        )
        log.save()
    except Exception as e:
        print(e, flush=True)
        log = ServiceLog.objects.create(
            content=f"Failed to send TOTP disabled email to {account.username} ({account.id}) due to :: {e}",
            severity=LogSeverity.ERROR
        )
        log.save()
    
    return JsonResponse({'status': 'SUCCESS'})