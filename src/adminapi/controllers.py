import os
import secrets
import traceback
import datetime
import pytz
import uuid

from django.core.exceptions import ObjectDoesNotExist
from django.http import JsonResponse
from django.db import IntegrityError
from django.core.cache import cache
from django.utils import timezone
from django.shortcuts import get_object_or_404
from django.utils.dateparse import parse_duration

from .models import Account, ServiceLog, SessionToken, CommonPasswords
from .enums.log_severity import LogSeverity
from .enums.account_status import AccountStatus

from .utils.generate_base_url import generate_base_url
from .utils.hash_email import hash_email
from .utils.hash_password import hash_password
from .utils.is_valid_email import is_valid_email
from .utils.is_valid_password import is_valid_password
from .utils.verify_password import verify_password
from .utils.generate_verification_url import generate_verification_url

from .services.get_country_from_ip import get_country_from_ip
from .services.generate_email_verification_token import generate_email_verification_token
from .services.request_encrypt import request_encrypt
from .services.request_decrypt import request_decrypt
from .services.send_email_with_content import send_email_with_content
from .services.verify_totp_code import verify_totp_code

from .create_default_admin import create_default_admin

from argon2.exceptions import VerifyMismatchError
from argon2 import PasswordHasher

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

    is_common = CommonPasswords.objects.filter(password=password).exists()
    return is_common

def _cache_login_attempt(ip_address):
    """
    Cache login attempts and returns a specific string status on how to handle logins after.

    Return Codes (string)
    - OK: Proceed to try login.
    - TIMEOUT: Login handler should reject the request.
    """
    max_login_attempts = int(os.environ.get('MAX_LOGIN_ATTEMPTS', '6'))
    timeout_seconds = int(os.environ.get('LOGIN_BRUTEFORCE_TIMEOUT', '60'))

    key = "login_" + ip_address
    current_attempts = int(cache.get(key, "0"))
    current_attempts += 1

    # NOTE: Currently, it will just let the user try for the next `timeout_seconds`
    # We can consider resetting the timeout counter if the user tries to login while timed-out
    if current_attempts >= max_login_attempts:
        return "TIMEOUT"

    cache.set(key, str(current_attempts), timeout_seconds)
    return "OK"

def _insert_session_token(new_token, account, client_info, country, days_until_expiry=30):
    # Hash the token using Argon2 with a pepper
    pepper_hex = os.environ.get('PEPPER_KEY', 'pepper-not-set')
    pepper_bytes = bytes.fromhex(pepper_hex)
    hasher = PasswordHasher()
    hashed_token = hasher.hash(new_token.encode() + pepper_bytes)

    # Calculate expiry date
    current_time = timezone.now()
    expiry_date = current_time + datetime.timedelta(days=days_until_expiry)

    encrypted_client_info = request_encrypt(str(account.id), client_info, str(account.id))
    encrypted_country = request_encrypt(str(account.id), country, str(account.id))

    # Save the session token to the database
    session_token = SessionToken.objects.create(
        account=account,
        hashed_token=hashed_token,
        encrypted_client_info=encrypted_client_info,
        encrypted_country=encrypted_country,
        expiry_date=expiry_date
    )
    session_token.save()

    log = ServiceLog.objects.create(
        content=f"{account.username} ({account.id}) logged in with new session token.",
        severity=LogSeverity.LOG
    )
    log.save()

    return session_token

def handle_login(username, password, second_fa_code, user_agent, ip_address):
    create_default_admin()
    try:
        login_procedural = _cache_login_attempt(ip_address)

        # TODO: Handle captcha request
        if login_procedural == "TIMEOUT":
            # TODO: Service warning? etc...
            log = ServiceLog.objects.create(
                content=f"{ip_address} attempted to login too many times into {username}.",
                severity=LogSeverity.LOG
            )
            log.save()
            return JsonResponse({'status': 'TIMEOUT'}, status=429)
        
        if len(username) < 4 or len(username) > 64:
            return JsonResponse({'status': 'BAD_USERNAME'}, status=400)

        if not is_valid_password(password):
            return JsonResponse({'status': 'BAD_PASSWORD'}, status=400)

        account = Account.objects.get(username=username)
        if account is None:
            return JsonResponse({'status': 'BAD_USERNAME'}, status=401)
        
        # Check if TOTP enabled, and handle...
        if account.totp_enabled and not second_fa_code:
            return JsonResponse({'status': 'TOTP_ENABLED'}, status=403)

        if not verify_password(account.hashed_password, password):
            return JsonResponse({'status': 'BAD_PASSWORD'}, status=401)

        if account.status != AccountStatus.OK:
            return JsonResponse({'status': 'LOCKED'}, status=401)
    
        if account.totp_enabled:
            verify_result = verify_totp_code(account.id, second_fa_code)
            verify_status = verify_result['status']
            if verify_status != 'SUCCESS':
                return JsonResponse({'status': 'ERROR'}, status=500)
            elif verify_status == "NO_TOKEN_SET":
                log = ServiceLog.objects.create(
                    content=f"Auth service mismatch with {account.username} ({account.id}); Where TOTP was enabled, but auth service deemed it not to be!",
                    severity=LogSeverity.CRITICAL
                )
                log.save()
                account.totp_enabled = False
                account.save()
            elif not verify_result['valid']:
                return JsonResponse({'status': 'BAD_TOTP'}, status=401)
        

        country = get_country_from_ip(ip_address)
        session_token = secrets.token_urlsafe(32)
        _insert_session_token(session_token, account, user_agent, country)

        try:
            email = request_decrypt(account.id, account.encrypted_email, account.id)
            send_email_with_content(email, 'New Login (Admin)!', f'Hello, we let you know you logged in at {country} ({ip_address}) with {user_agent}!')
        except Exception as e:
            print(e, flush=True)
            log = ServiceLog.objects.create(
                content=f"Failed to notify login activity to {account.username} ({account.id}) due to :: {e}",
                severity=LogSeverity.ERROR
            )
            log.save()

        return JsonResponse({'status': 'SUCCESS', 'token': session_token}, status=200)
    except ObjectDoesNotExist:
        return JsonResponse({'status': 'BAD_USERNAME'}, status=401)
    except Exception as e:
        log_message = f"Tried to login {username}, but failed due to :: {e}\n\n{traceback.format_exc()}"
        print(log_message, flush=True)
        log = ServiceLog.objects.create(
            content=log_message,
            severity=LogSeverity.ERROR
        )
        log.save()
        return JsonResponse({'status': 'ERROR'}, status=500)

def handle_registration(username, email, password):
    try:
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

            response = send_email_with_content(email, email_header, email_content)
            if not response['success']:
                return JsonResponse({'status': 'ERROR'}, status=500)
            cache.set(f"email_verification_{str(generated_uuid)}", True, timeout=120)

        except Exception as e:
            log_message = f"Tried to send notification email to {email}, but failed due to :: {e}\n\n{traceback.format_exc()}"
            print(log_message, flush=True)
            log = ServiceLog.objects.create(
                content=log_message,
                severity=LogSeverity.ERROR
            )
            log.save()
            return JsonResponse({'status': 'ERROR'}, status=500)

        # Attempt to insert into database
        account = Account.objects.create(
            id=generated_uuid,
            username=username,
            hashed_password=hashed_password,
            encrypted_email=encrypted_email,
            hashed_email=hashed_email
        )
        account.save()

        log = ServiceLog.objects.create(
            content=f"New user {username} created with uuid {account.id}.",
            severity=LogSeverity.LOG
        )
        log.save()

        return JsonResponse({'status': 'SUCCESS'})
    except IntegrityError as e:
        # If username/email conflict
        if 'username' in str(e):
            return JsonResponse({'status': 'USERNAME_TAKEN'}, status=409)
        if 'hashed_email' in str(e):
            return JsonResponse({'status': 'EMAIL_TAKEN'}, status=409)
    except Exception as e:
        log_message = f"Tried to register {username}, but failed due to :: {e}\n\n{traceback.format_exc()}"
        print(log_message, flush=True)
        log = ServiceLog.objects.create(
            content=log_message,
            severity=LogSeverity.ERROR
        )
        log.save()
        return JsonResponse({'status': 'ERROR'}, status=500)
    # Shouldn't reach here...
    return JsonResponse({'status': 'ERROR CONTACT ADMIN'}, status=500)

def validate_session_token(username, client_info, plaintext_token):
    """
    Validate a session token, returns the Account ORM object if successful.
    Returns None otherwise
    """
    try:
        # Retrieve the user's account based on the username
        account = Account.objects.get(username=username)

        # Get the pepper from the environment variable
        pepper_hex = os.environ.get('PEPPER_KEY', 'pepper-not-set')
        pepper_bytes = bytes.fromhex(pepper_hex)

        # Iterate through all session tokens associated with the user's account
        for session_token in SessionToken.objects.filter(account=account):
            decrypted_client_info = request_decrypt(str(account.id), session_token.encrypted_client_info, str(account.id))

            if session_token.expiry_date < timezone.now():
                session_token.delete()
                log = ServiceLog.objects.create(
                    content=f"Session Token Expired for user :: {username} ({account.id})",
                    severity=LogSeverity.VERBOSE
                )
                log.save()
                continue

            # Validate the hashed token against the session token's hashed token
            try:
                hasher = PasswordHasher()
                if hasher.verify(session_token.hashed_token, plaintext_token.encode() + pepper_bytes):
                    if not decrypted_client_info == client_info:
                        # Token is invalid since client information doesnt match
                        session_token.delete()
                        log = ServiceLog.objects.create(
                            content=f"Client Information Mismatch for user :: {username} ({account.id})",
                            severity=LogSeverity.WARNING
                        )
                        log.save()
                        return None

                    # Token is valid
                    return account
            except VerifyMismatchError:
                continue

        # No matching valid token found
        return None

    except ObjectDoesNotExist:
        # User account not found
        return None
