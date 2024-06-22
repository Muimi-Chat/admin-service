import json
import traceback

from django.core.cache import cache
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from .services.send_email_with_content import send_email_with_content

from .enums.access_attribute import AccessAttribute
from .enums.log_severity import LogSeverity
from .enums.account_status import AccountStatus
from .models import AccountAccess, ServiceLog, Account

from .controllers import validate_session_token

from .services.request_decrypt import request_decrypt

from .repository.user.disable_user_verification import disable_user_verification
from .repository.user.get_user_by_id import get_user_by_id
from .repository.user.disable_user_totp import disable_user_totp
from .repository.user.set_user_status import set_user_status

import uuid

def _can_perform_action(account: Account, action: AccessAttribute):
    return AccountAccess.objects.filter(
        account=account,
        access_attribute=action
    ).exists()

def _is_valid_uuid(uuid_string):
    try:
        uuid.UUID(str(uuid_string))
        return True
    except ValueError:
        return False

@csrf_exempt
def change_user_status(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'ERROR'}, status=404)

    data = json.loads(request.body)
    session_token = request.headers.get('session-token', '')
    user_agent = request.META['HTTP_USER_AGENT']
    self_username = data.get('self_username', '')
    target_user_id = data.get('target_user_id', '')
    status = data.get('status', '').upper()

    account = validate_session_token(self_username, user_agent, session_token)
    if account is None:
        return JsonResponse({'status': 'BAD_SESSION_TOKEN'}, status=401)
    
    if account.status != AccountStatus.OK:
        return JsonResponse({'status': 'ACCOUNT_DISABLED'}, status=403)
    if not account.authenticated:
        return JsonResponse({'status': 'ACCOUNT_NOT_AUTHENTICATED'}, status=403)
    
    if not _can_perform_action(account, AccessAttribute.CHANGE_USER_STATUS):
        return JsonResponse({'status': 'PERMISSION_DENIED'}, status=403)
    
    if not (status == 'OK' or status == 'LOCKED' or status == 'BANNED'):
        return JsonResponse({'status': 'INVALID_STATUS'}, status=400)
    
    if not _is_valid_uuid(target_user_id):
        return JsonResponse({'status': 'INVALID_USER_ID'}, status=400)
    
    target_user = None
    try:
        target_user = get_user_by_id(target_user_id)
        if target_user is None:
            return JsonResponse({'status': 'USER_NOT_FOUND'}, status=404)
    except Exception as e:
        print(e, flush=True)
        ServiceLog.objects.create(
            content=f"User {account.username} ({account.id}) failed to set user status :: {traceback.format_exc()}",
            severity=LogSeverity.ERROR
        )
        return JsonResponse({'status': 'ERROR'}, status=500)

    try:
        set_user_status(target_user_id, status)
        ServiceLog.objects.create(
            content=f"User {account.username} ({account.id}) set user status to {status} for {target_user['username']} ({target_user_id})",
            severity=LogSeverity.VERBOSE
        )
    except Exception as e:
        print(e, flush=True)
        ServiceLog.objects.create(
            content=f"User {account.username} ({account.id}) failed to set user status :: {traceback.format_exc()}",
            severity=LogSeverity.ERROR
        )
        return JsonResponse({'status': 'ERROR'}, status=500)

    try:
        email = request_decrypt(target_user_id, target_user['encrypted_email'], target_user_id)
        email_content = f"Dear {target_user['username']},\n\nYour account have been {status} by our admin.\n\nIf you believe this is a mistake, please contact support."
        email_header = "Account status changed by Admin"
        response = send_email_with_content(email, email_header, email_content)
        if not response['success']:
            return JsonResponse({'status': 'ERROR'}, status=500)
    except Exception as e:
        print(e, flush=True)
        ServiceLog.objects.create(
            severity=LogSeverity.ERROR,
            content=f'Failed to notify {target_user['username']} ({target_user_id}) about {status} change :: {traceback.format_exc()}',
        )

    return JsonResponse({'status': 'SUCCESS'})

@csrf_exempt
def remove_user_verification(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'ERROR'}, status=404)

    data = json.loads(request.body)
    session_token = request.headers.get('session-token', '')
    user_agent = request.META['HTTP_USER_AGENT']
    self_username = data.get('self_username', '')
    target_user_id = data.get('target_user_id', '')

    account = validate_session_token(self_username, user_agent, session_token)
    if account is None:
        return JsonResponse({'status': 'BAD_SESSION_TOKEN'}, status=401)
    
    if account.status != AccountStatus.OK:
        return JsonResponse({'status': 'ACCOUNT_DISABLED'}, status=403)
    if not account.authenticated:
        return JsonResponse({'status': 'ACCOUNT_NOT_AUTHENTICATED'}, status=403)
    
    if not _can_perform_action(account, AccessAttribute.REVOKE_USER_VERIFICATION_STATUS):
        return JsonResponse({'status': 'PERMISSION_DENIED'}, status=403)

    if not _is_valid_uuid(target_user_id):
        return JsonResponse({'status': 'INVALID_USER_ID'}, status=400)

    target_user = None
    try:
        target_user = get_user_by_id(target_user_id)
        if target_user is None:
            return JsonResponse({'status': 'USER_NOT_FOUND'}, status=404)
    except Exception as e:
        print(e, flush=True)
        ServiceLog.objects.create(
            content=f"User {account['username']} ({account.id}) failed to remove user verification :: {traceback.format_exc()}",
            severity=LogSeverity.ERROR
        )
        return JsonResponse({'status': 'ERROR'}, status=500)

    if not target_user['authenticated']:
        return JsonResponse({'status': 'USER_NOT_AUTHENTICATED'}, status=403)

    try:
        disable_user_verification(target_user_id)
        ServiceLog.objects.create(
            content=f"User {account.username} ({account.id}) removed user verification for {target_user['username']} ({target_user_id})",
            severity=LogSeverity.VERBOSE
        )
    except Exception as e:
        print(e, flush=True)
        ServiceLog.objects.create(
            content=f"User {account.username} ({account.id}) failed to remove user verification for {target_user['username']} ({target_user_id}) :: {traceback.format_exc()}",
            severity=LogSeverity.ERROR
        )
        return JsonResponse({'status': 'ERROR'}, status=500)
    try:
        email = request_decrypt(target_user_id, target_user['encrypted_email'], target_user_id)
        email_content = f"Dear {target_user['username']},\n\nYour account has been set to unverified by an admin.\n\nIf you believe this is a mistake, please contact support."
        email_header = "Verification Status Removed by Admin"
        response = send_email_with_content(email, email_header, email_content)
        if not response['success']:
            return JsonResponse({'status': 'ERROR'}, status=500)
    except Exception as e:
        print(e, flush=True)
        ServiceLog.objects.create(
            severity=LogSeverity.ERROR,
            content=f'Failed to notify {target_user['username']} ({target_user_id}) about verification removal :: {traceback.format_exc()}',
        )
    return JsonResponse({'status': 'SUCCESS'})
    

@csrf_exempt
def remove_user_totp(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'ERROR'}, status=404)

    data = json.loads(request.body)
    session_token = request.headers.get('session-token', '')
    user_agent = request.META['HTTP_USER_AGENT']
    self_username = data.get('self_username', '')
    target_user_id = data.get('target_user_id', '')

    account = validate_session_token(self_username, user_agent, session_token)
    if account is None:
        return JsonResponse({'status': 'BAD_SESSION_TOKEN'}, status=401)
    
    if account.status != AccountStatus.OK:
        return JsonResponse({'status': 'ACCOUNT_DISABLED'}, status=403)
    if not account.authenticated:
        return JsonResponse({'status': 'ACCOUNT_NOT_AUTHENTICATED'}, status=403)
    
    if not _can_perform_action(account, AccessAttribute.REVOKE_USER_TOTP):
        return JsonResponse({'status': 'PERMISSION_DENIED'}, status=403)

    if not _is_valid_uuid(target_user_id):
        return JsonResponse({'status': 'INVALID_USER_ID'}, status=400)

    # Check if already disabled, if not disable
    target_user = None
    try:
        target_user = get_user_by_id(target_user_id)
        if target_user is None:
            return JsonResponse({'status': 'USER_NOT_FOUND'}, status=404)
        if not target_user['totp_enabled']:
            return JsonResponse({'status': 'USER_NOT_TOTP_ENABLED'}, status=400)
        
        affected = disable_user_totp(target_user_id)
        if not affected:
            return JsonResponse({'status': 'INTERNAL_SERVER_ERROR'}, status=500)

        ServiceLog.objects.create(
            severity=LogSeverity.VERBOSE,
            content=f'{account.username} ({account.id}) Removed TOTP from user {target_user['username']} ({target_user_id})',
        )
    except Exception as e:
        print(e, flush=True)
        ServiceLog.objects.create(
            severity=LogSeverity.ERROR,
            content=f'{account.username} ({account.id}) Failed to remove TOTP from user {target_user['username']} ({target_user_id}) :: {traceback.format_exc()}',
        )
        return JsonResponse({'status': 'INTERNAL_SERVER_ERROR'}, status=500)
    
    # Notify disabled TOTP via email
    try:
        email = request_decrypt(target_user_id, target_user['encrypted_email'], target_user_id)
        email_content = f"Dear {target_user['username']},\n\nYour TOTP has been removed by an admin.\n\nIf you believe this is a mistake, please contact support."
        email_header = "TOTP Removed by Admin"
        response = send_email_with_content(email, email_header, email_content)
        if not response['success']:
            return JsonResponse({'status': 'ERROR'}, status=500)
    except Exception as e:
        print(e, flush=True)
        ServiceLog.objects.create(
            severity=LogSeverity.ERROR,
            content=f'Failed to notify {target_user['username']} ({target_user_id}) about TOTP removal :: {traceback.format_exc()}',
        )
        
    return JsonResponse({'status': 'SUCCESS'})

