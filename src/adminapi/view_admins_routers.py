import json
import traceback

from django.core.cache import cache
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from .enums.access_attribute import AccessAttribute
from .enums.log_severity import LogSeverity
from .enums.account_status import AccountStatus
from .models import AccountAccess, ServiceLog, Account

from .controllers import validate_session_token

from .services.request_decrypt import request_decrypt

from django.utils import timezone

from .repository.chat.get_chat_users import get_chat_users
from .repository.user.get_users import get_users

from asgiref.sync import sync_to_async

from django.db.models import Prefetch

from concurrent.futures import ThreadPoolExecutor

def sync_request_decrypt(account_id, encrypted_email):
    with ThreadPoolExecutor() as pool:
        result = pool.submit(request_decrypt, account_id, encrypted_email, account_id).result()
    return result

def _get_all_admins():
    accounts = Account.objects.prefetch_related(
        Prefetch('accountaccess_set', queryset=AccountAccess.objects.only('access_attribute'))
    ).all()

    decrypted_emails = []

    for account in accounts:
        decrypted_email = sync_request_decrypt(account.id, account.encrypted_email)
        decrypted_emails.append(decrypted_email)

    serialized_accounts = []

    for index, account in enumerate(accounts):
        serialized_account = {
            'id': str(account.id),
            'username': account.username,
            'email': decrypted_emails[index],
            'createdAt': account.created_at.isoformat(),
            'status': account.status,
            'authenticated': account.authenticated,
            'totpEnabled': account.totp_enabled,
            'accessAttributes': [access.access_attribute for access in account.accountaccess_set.all()]
        }
        serialized_accounts.append(serialized_account)

    return serialized_accounts

def _can_perform_action(account: Account, action: AccessAttribute):
    return AccountAccess.objects.filter(
        account=account,
        access_attribute=action
    ).exists()

@csrf_exempt
def view_admins(request):
    try:
        return view_admins_actual(request)
    except Exception as e:
        traceback.print_exc()
        ServiceLog.objects.create(
            content=f"Error in viewing admins: {str(e)}",
            severity=LogSeverity.CRITICAL
        )
        return JsonResponse({'status': 'ERROR'}, status=500)

@csrf_exempt
def view_admins_actual(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'ERROR'}, status=404)

    data = json.loads(request.body)
    session_token = request.headers.get('session-token', '')
    user_agent = request.META['HTTP_USER_AGENT']
    self_username = data.get('self_username', '')
    force_refresh = data.get('force_refresh', False)

    account = validate_session_token(self_username, user_agent, session_token)
    if account is None:
        return JsonResponse({'status': 'BAD_SESSION_TOKEN'}, status=401)
    
    if account.status != AccountStatus.OK:
        return JsonResponse({'status': 'ACCOUNT_DISABLED'}, status=403)
    if not account.authenticated:
        return JsonResponse({'status': 'ACCOUNT_NOT_AUTHENTICATED'}, status=403)
    
    if not account.totp_enabled:
        return JsonResponse({'status': 'ACCOUNT_NOT_TOTP_ENABLED'}, status=403)

    cached_result = cache.get('view_admins_list')
    admins = []
    if cached_result:
        admins = json.loads(cached_result)
    else:
        try:
            admins = _get_all_admins()
            cache.delete('view_admins_list')
            cache.set('view_admins_list', json.dumps(admins), timeout=5)
        except Exception as e:
            print(e, flush=True)
            ServiceLog.objects.create(
                content=f"User {account.username} ({account.id}) failed to refresh admin list :: {traceback.format_exc()}",
                severity=LogSeverity.ERROR
            )
            return JsonResponse({'status': 'ERROR'}, status=500)
        
    return JsonResponse({
        'status': 'SUCCESS',
        'admins': admins,
        'canRevokeTOTP': _can_perform_action(account, AccessAttribute.REVOKE_ADMIN_2FA),
        'canRevokeSessions': _can_perform_action(account, AccessAttribute.REVOKE_ADMIN_SESSIONS),
        'canRevokeVerification': _can_perform_action(account, AccessAttribute.REVOKE_ADMIN_VERIFICATION),
        'canChangeAccess': _can_perform_action(account, AccessAttribute.MODIFY_ADMIN_ACCESS_ATTRIBUTE),
        'canDeactivateAccount': _can_perform_action(account, AccessAttribute.DEACTIVATE_ADMIN_ACCOUNT),
    }, safe=False)

