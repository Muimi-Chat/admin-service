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
def disable_admin_verification(request):
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
    
    if not _can_perform_action(account, AccessAttribute.REVOKE_ADMIN_VERIFICATION):
        return JsonResponse({'status': 'PERMISSION_DENIED'}, status=403)
    if not account.totp_enabled:
        return JsonResponse({'status': 'VERIFICATION_DISABLED'}, status=403)
    
    if not _is_valid_uuid(target_user_id):
        return JsonResponse({'status': 'INVALID_USER_ID'}, status=400)
    
    if account.id == target_user_id:
        return JsonResponse({'status': 'CANT_TARGET_SELF'}, status=400)
    
    target_user = None
    try:
        target_user = Account.objects.filter(id=target_user_id).first()
        if target_user is None:
            return JsonResponse({'status': 'USER_NOT_FOUND'}, status=404)
        
        if target_user.authenticated is False:
            return JsonResponse({'status': 'ALREADY_DISABLED'}, status=400)

        target_user.authenticated = False
        target_user.save()
    except Exception as e:
        print(e, flush=True)
        ServiceLog.objects.create(
            content=f"User {account.username} ({account.id}) failed to set disable admin verification :: {traceback.format_exc()}",
            severity=LogSeverity.ERROR
        )
        return JsonResponse({'status': 'ERROR'}, status=500)

    try:
        email = request_decrypt(target_user_id, target_user.encrypted_email, target_user_id)
        email_content = f"Dear {target_user.username},\n\nYour account's have been unverified by {account.username}.\n\nChange your account's password to verify again."
        email_header = "Admin Account Unverified"
        response = send_email_with_content(email, email_header, email_content)
        if not response['success']:
            return JsonResponse({'status': 'ERROR'}, status=500)
    except Exception as e:
        print(e, flush=True)
        ServiceLog.objects.create(
            severity=LogSeverity.ERROR,
            content=f'Failed to notify {target_user.username} ({target_user_id}) verification Disabled :: {traceback.format_exc()}',
        )

    ServiceLog.objects.create(
        severity=LogSeverity.VERBOSE,
        content=f'User {account.username} ({account.id}) unverified for admin {target_user.username} ({target_user_id})',
    )

    return JsonResponse({'status': 'SUCCESS'})