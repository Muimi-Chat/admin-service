import json

from django.db import transaction
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from .enums.access_attribute import AccessAttribute
from .enums.log_severity import LogSeverity
from .enums.account_status import AccountStatus
from .models import AccountAccess, Account, ServiceLog

from .controllers import validate_session_token
from .translate_integers_to_access_attributes import translate_integers_to_access_attributes

def _update_account_access(account, desired_access_attributes):
    # Get current AccessAttribute values associated with the account
    current_access_attributes = set(
        AccountAccess.objects.filter(account=account).values_list('access_attribute', flat=True)
    )

    desired_access_set = set(desired_access_attributes)

    attributes_to_add = desired_access_set - current_access_attributes
    attributes_to_remove = current_access_attributes - desired_access_set

    with transaction.atomic():
        # Remove attributes not in desired set
        AccountAccess.objects.filter(account=account, access_attribute__in=attributes_to_remove).delete()

        # Add attributes not in current set
        for attribute in attributes_to_add:
            AccountAccess.objects.create(account=account, access_attribute=attribute)

@csrf_exempt
def toggle_admin_access(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'ERROR'}, status=404)

    data = json.loads(request.body)
    session_token = request.headers.get('session-token', '')
    user_agent = request.META['HTTP_USER_AGENT']
    self_username = data.get('self_username', '')
    target_user_id = data.get('target_user_id', '')

    access_attribute = None
    try:
        access_attribute = AccessAttribute(data.get('access_attribute', 0))
    except ValueError:
        return JsonResponse({'status': 'INVALID_ACCESS_ATTRIBUTE'}, status=400)

    if access_attribute is None:
        return JsonResponse({'status': 'INVALID_ACCESS_ATTRIBUTE'}, status=400)

    account = validate_session_token(self_username, user_agent, session_token)
    if account is None:
        return JsonResponse({'status': 'BAD_SESSION_TOKEN'}, status=401)
    
    if account.status != AccountStatus.OK:
        return JsonResponse({'status': 'ACCOUNT_DISABLED'}, status=403)
    if not account.authenticated:
        return JsonResponse({'status': 'ACCOUNT_NOT_AUTHENTICATED'}, status=403)

    has_permission = AccountAccess.objects.filter(
        account=account,
        access_attribute=AccessAttribute.MODIFY_ADMIN_ACCESS_ATTRIBUTE
    ).exists()

    if not has_permission:
        return JsonResponse({'status': 'PERMISSION_DENIED'}, status=403)
    if not account.totp_enabled:
        return JsonResponse({'status': 'ACCOUNT_NOT_2FA_ENABLED'}, status=403)

    target_account = Account.objects.filter(id=target_user_id).first()
    if target_account is None:
        return JsonResponse({'status': 'ACCOUNT_NOT_FOUND'}, status=404)
    if target_account.username == account.username:
        return JsonResponse({'status': 'CANT_MODIFY_SELF'}, status=406)
    
    if AccountAccess.objects.filter(
        account=target_account,
        access_attribute=access_attribute
    ).exists():
        AccountAccess.objects.filter(
            account=target_account,
            access_attribute=access_attribute
        ).first().delete()
    else:
        AccountAccess.objects.create(
            account=target_account,
            access_attribute=access_attribute
        )

    ServiceLog.objects.create(
        content=f'Admin {account.username} toggled access attributes for {target_account.username} to {access_attribute}',
        severity=LogSeverity.VERBOSE
    )
    return JsonResponse({'status': 'SUCCESS'})

@csrf_exempt
def control_admin_access(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'ERROR'}, status=404)

    data = json.loads(request.body)
    session_token = request.headers.get('session-token', '')
    user_agent = request.META['HTTP_USER_AGENT']
    self_username = data.get('self_username', '')
    target_username = data.get('target_username', '')
    access_attributes = []
    try:
        access_attributes = translate_integers_to_access_attributes(data.get('access_attributes', []))
    except ValueError:
        return JsonResponse({'status': 'INVALID_ACCESS_ATTRIBUTE'}, status=400)

    if len(access_attributes) == 0:
        return JsonResponse({'status': 'INVALID_ACCESS_ATTRIBUTE'}, status=400)

    account = validate_session_token(self_username, user_agent, session_token)
    if account is None:
        return JsonResponse({'status': 'BAD_SESSION_TOKEN'}, status=401)
    
    if account.status != AccountStatus.OK:
        return JsonResponse({'status': 'ACCOUNT_DISABLED'}, status=403)
    if not account.authenticated:
        return JsonResponse({'status': 'ACCOUNT_NOT_AUTHENTICATED'}, status=403)

    has_permission = AccountAccess.objects.filter(
        account=account,
        access_attribute=AccessAttribute.MODIFY_ADMIN_ACCESS_ATTRIBUTE
    ).exists()

    if not has_permission:
        return JsonResponse({'status': 'PERMISSION_DENIED'}, status=403)
    if not account.totp_enabled:
        return JsonResponse({'status': 'ACCOUNT_NOT_2FA_ENABLED'}, status=403)

    target_account = Account.objects.filter(username=target_username).first()
    if target_account is None:
        return JsonResponse({'status': 'ACCOUNT_NOT_FOUND'}, status=404)
    if target_account.username == account.username:
        return JsonResponse({'status': 'CANT_MODIFY_SELF'}, status=406)

    _update_account_access(target_account, access_attributes)

    ServiceLog.objects.create(
        content=f'Admin {account.username} changed access attributes for {target_account.username} to {access_attributes}',
        severity=LogSeverity.VERBOSE
    )
    return JsonResponse({'status': 'SUCCESS'})

