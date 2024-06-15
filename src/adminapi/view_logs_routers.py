import json
import traceback

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from .enums.access_attribute import AccessAttribute
from .enums.log_severity import LogSeverity
from .enums.account_status import AccountStatus
from .models import AccountAccess, ServiceLog

from .controllers import validate_session_token

from django.utils import timezone

from .repository.user.get_user_logs import get_user_logs
from .repository.chat.get_chat_logs import get_chat_logs

def _fetch_logs():
    queryset = ServiceLog.objects.all()
    return queryset.order_by('-created_at')

def _can_view_admin_logs(account):
    return AccountAccess.objects.filter(
        account=account,
        access_attribute=AccessAttribute.VIEW_ADMIN_LOGS
    ).exists()

@csrf_exempt
def view_logs(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'ERROR'}, status=404)

    data = json.loads(request.body)
    session_token = request.headers.get('session-token', '')
    user_agent = request.META['HTTP_USER_AGENT']
    self_username = data.get('self_username', '')

    target = data.get('target', 'admin').lower()

    account = validate_session_token(self_username, user_agent, session_token)
    if account is None:
        return JsonResponse({'status': 'BAD_SESSION_TOKEN'}, status=401)
    
    if account.status != AccountStatus.OK:
        return JsonResponse({'status': 'ACCOUNT_DISABLED'}, status=403)
    if not account.authenticated:
        return JsonResponse({'status': 'ACCOUNT_NOT_AUTHENTICATED'}, status=403)

    log_list = []
    try:
        if target == 'admin':
            if not _can_view_admin_logs(account):
                return JsonResponse({'status': 'PERMISSION_DENIED'}, status=403)
            logs = _fetch_logs()
            log_list = list(logs.values())
        elif target == 'user':
            log_list = get_user_logs()
        elif target == 'chat':
            log_list = get_chat_logs()
        else:
            return JsonResponse({'status': 'INVALID_TARGET'}, status=400)
    except Exception as e:
        print(f"Error trying to fetch logs :: {traceback.format_exc()}", flush=True)
        ServiceLog.objects.create(content=f"Error trying to fetch logs :: {traceback.format_exc()}",severity=LogSeverity.WARNING)
        return JsonResponse({'status': 'ERROR'}, status=500)

    return JsonResponse({
        'status': 'SUCCESS',
        'logs': log_list
    }, safe=False)

