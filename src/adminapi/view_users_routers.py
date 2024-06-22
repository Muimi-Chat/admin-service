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

import concurrent.futures

def _get_users_list():
    users_list = get_users()
    chat_users_list = get_chat_users()
    
    print("Fetching users list...", flush=True)
    def process_user(user):
        for chat_user in chat_users_list:
            if user['id'] == chat_user['id']:
                user_id = user['id']
                print(f"Found {user_id}", flush=True)
                email = request_decrypt(user_id, user['encrypted_email'], user_id)
                return {
                    'id': str(user_id),
                    'username': user['username'],
                    'email': email,
                    'totpEnabled': user['totp_enabled'],
                    'createdAt': user['created_at'].isoformat(),
                    'status': user['status'],
                    'authenticated': user['authenticated'],
                    'token': chat_user['token']
                }
        # If user is not found in chat_users_list, populate with 'Not logged in yet'
        user_id = user['id']
        print(f"User {user_id} not found in chat_users_list. Setting token to 'Not logged in yet'", flush=True)
        email = request_decrypt(user_id, user['encrypted_email'], user_id)
        return {
            'id': str(user_id),
            'username': user['username'],
            'email': email,
            'totpEnabled': user['totp_enabled'],
            'createdAt': user['created_at'].isoformat(),
            'status': user['status'],
            'authenticated': user['authenticated'],
            'token': 'Not logged in yet; Undefined'
        }
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = executor.map(process_user, users_list)
    
    print("Merging with chat users...", flush=True)
    merged_list = [result for result in results if result is not None]
    
    return merged_list

def _can_perform_action(account: Account, action: AccessAttribute):
    return AccountAccess.objects.filter(
        account=account,
        access_attribute=action
    ).exists()


@csrf_exempt
def view_users(request):
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
    
    if force_refresh:
        recently_refreshed = cache.get(f'refresh_user_list_{str(account.id)}')
        if recently_refreshed:
            return JsonResponse({'status': 'RECENTLY_REFRESHED'}, status=429)
        cache.set(f'refresh_user_list_{str(account.id)}', True, timeout=20)
        ServiceLog.objects.create(
            content=f"User {account.username} ({account.id}) requested refresh of user list",
            severity=LogSeverity.VERBOSE
        )

    cached_result = cache.get('view_users_list')
    users = []
    if cached_result and not force_refresh:
        users = json.loads(cached_result)
    else:
        try:
            users = _get_users_list()
            cache.delete('view_users_list')
            cache.set('view_users_list', json.dumps(users), timeout=301)
        except Exception as e:
            print(e, flush=True)
            ServiceLog.objects.create(
                content=f"User {account.username} ({account.id}) failed to refresh user list :: {traceback.format_exc()}",
                severity=LogSeverity.ERROR
            )
            return JsonResponse({'status': 'ERROR'}, status=500)
        
    return JsonResponse({
        'status': 'SUCCESS',
        'users': users,
        'canSetTokens': _can_perform_action(account, AccessAttribute.SET_USER_TOKEN),
        'canRevokeTOTP': _can_perform_action(account, AccessAttribute.REVOKE_USER_TOTP),
        'canRevokeSessions': _can_perform_action(account, AccessAttribute.REVOKE_USER_SESSIONS),
        'canRevokeVerification': _can_perform_action(account, AccessAttribute.REVOKE_USER_VERIFICATION_STATUS),
        'canChangeStatus': _can_perform_action(account, AccessAttribute.CHANGE_USER_STATUS),
    }, safe=False)

