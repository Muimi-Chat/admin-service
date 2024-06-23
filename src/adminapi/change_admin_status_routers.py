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
def change_admin_status(request):
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
    
    if not _can_perform_action(account, AccessAttribute.CHANGE_ADMIN_ACTIVATION_STATUS):
        return JsonResponse({'status': 'PERMISSION_DENIED'}, status=403)
    if not account.totp_enabled:
        return JsonResponse({'status': 'TOTP_DISABLED'}, status=403)
    
    if not (status == 'OK' or status == 'DEACTIVATED'):
        return JsonResponse({'status': 'INVALID_STATUS'}, status=400)
    
    if not _is_valid_uuid(target_user_id):
        return JsonResponse({'status': 'INVALID_USER_ID'}, status=400)
    
    if account.id == target_user_id:
        return JsonResponse({'status': 'CANT_TARGET_SELF'}, status=400)

    try:
        account_status = AccountStatus[status]
    except KeyError:
        return JsonResponse({'status': 'INVALID_STATUS'}, status=400)
    
    target_user = None
    try:
        target_user = Account.objects.filter(id=target_user_id).first()
        if target_user is None:
            return JsonResponse({'status': 'USER_NOT_FOUND'}, status=404)
        target_user.status = account_status
        target_user.save()
    except Exception as e:
        print(e, flush=True)
        ServiceLog.objects.create(
            content=f"User {account.username} ({account.id}) failed to set user status :: {traceback.format_exc()}",
            severity=LogSeverity.ERROR
        )
        return JsonResponse({'status': 'ERROR'}, status=500)

    try:
        email = request_decrypt(target_user_id, target_user.encrypted_email, target_user_id)
        email_content = f"Dear {target_user.username},\n\nYour account have been {status} by {account.username}."
        email_header = f"Admin Account status change into {status}"
        response = send_email_with_content(email, email_header, email_content)
        if not response['success']:
            return JsonResponse({'status': 'ERROR'}, status=500)
    except Exception as e:
        print(e, flush=True)
        ServiceLog.objects.create(
            severity=LogSeverity.ERROR,
            content=f'Failed to notify {target_user.username} ({target_user_id}) about {status} change :: {traceback.format_exc()}',
        )

    ServiceLog.objects.create(
        severity=LogSeverity.VERBOSE,
        content=f'User {account.username} ({account.id}) set status for admin {target_user.username} ({target_user_id}) to {status}',
    )

    return JsonResponse({'status': 'SUCCESS'})