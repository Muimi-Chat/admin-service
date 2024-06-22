import os
import json
import uuid
import traceback

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from .utils.generate_base_url import generate_base_url

from .enums.access_attribute import AccessAttribute
from .enums.log_severity import LogSeverity
from .enums.account_status import AccountStatus
from .models import AccountAccess, Account, CommonPasswords, ServiceLog

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

@csrf_exempt
def create_new_admin(request):
    try:
        return register_new_admin(request)
    except Exception as e:
        print(f'ERROR: {traceback.format_exc()}')
        return JsonResponse({'status': 'ERROR'}, status=500)

@csrf_exempt
def register_new_admin(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'ERROR'}, status=404)

    data = json.loads(request.body)
    session_token = request.headers.get('session-token', '')
    user_agent = request.META['HTTP_USER_AGENT']
    self_username = data.get('self_username', '')
    username = data.get('username', '')
    password = data.get('password', '')
    email = data.get('email', '')

    account = validate_session_token(self_username, user_agent, session_token)
    if account is None:
        return JsonResponse({'status': 'BAD_SESSION_TOKEN'}, status=401)
    
    if account.status != AccountStatus.OK:
        return JsonResponse({'status': 'ACCOUNT_DISABLED'}, status=403)
    if not account.authenticated:
        return JsonResponse({'status': 'ACCOUNT_NOT_AUTHENTICATED'}, status=403)

    has_permission = AccountAccess.objects.filter(
        account=account,
        access_attribute=AccessAttribute.CREATE_ADMIN_ACCOUNT
    ).exists()

    if not has_permission:
        return JsonResponse({'status': 'PERMISSION_DENIED'}, status=403)
    if not account.totp_enabled:
        return JsonResponse({'status': 'ACCOUNT_NOT_2FA_ENABLED'}, status=403)
    
    if len(username) < 4 or len(username) > 64:
        return JsonResponse({'status': 'BAD_USERNAME'}, status=400)

    if not is_valid_email(email) or len(email) > 256:
        return JsonResponse({'status': 'BAD_EMAIL'}, status=400)

    if not is_valid_password(password):
        return JsonResponse({'status': 'BAD_PASSWORD'}, status=400)
    
    if _is_common_password(password):
        return JsonResponse({'status': 'COMMON_PASSWORD'}, status=406)
    
    generated_uuid = uuid.uuid4()
    hashed_email = hash_email(email)
    encrypted_email = request_encrypt(str(generated_uuid), email, str(generated_uuid))
    hashed_password = hash_password(password)


    try:
        website_url = generate_base_url()
        email_content = f"Your admin username and password is {username} and {password}. Please login at {website_url} and change your password to get started."
        email_header = "Muimi Admin"

        send_email_with_content(email, email_header, email_content)
    except Exception as e:
        log_message = f"Tried to send notification email to {email}, but failed due to :: {e}\n\n{traceback.format_exc()}"
        print(log_message, flush=True)
        log = ServiceLog.objects.create(
            content=log_message,
            severity=LogSeverity.ERROR
        )
        log.save()

    # Attempt to insert into database
    Account.objects.create(
        id=generated_uuid,
        username=username,
        hashed_password=hashed_password,
        encrypted_email=encrypted_email,
        hashed_email=hashed_email
    )

    ServiceLog.objects.create(
        content=f"New admin {username} created with uuid {account.id}. By {self_username} ({account.id})",
        severity=LogSeverity.LOG
    )

    return JsonResponse({'status': 'SUCCESS'})

