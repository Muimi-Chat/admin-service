import os
import uuid

from django.db import transaction

from .enums.access_attribute import AccessAttribute
from .models import Account, ServiceLog, AccountAccess
from .enums.log_severity import LogSeverity

from .utils.hash_email import hash_email
from .utils.hash_password import hash_password

from .services.request_encrypt import request_encrypt

def create_default_admin():
    if Account.objects.exists():
        return

    email = os.environ.get('DEFAULT_ADMIN_EMAIL', '')
    password = os.environ.get('DEFAULT_ADMIN_PASSWORD', '')
    username = os.environ.get('DEFAULT_ADMIN_USERNAME', '')

    if not email or not password or not username:
        print("Skipping default admin creation due to missing environment variables.", flush=True)
        return

    generated_uuid = uuid.uuid4()
    hashed_email = hash_email(email)
    encrypted_email = request_encrypt(str(generated_uuid), email, str(generated_uuid))
    hashed_password = hash_password(password)

    with transaction.atomic():
        account = Account.objects.create(
            id=generated_uuid,
            username=username,
            hashed_password=hashed_password,
            encrypted_email=encrypted_email,
            hashed_email=hashed_email
        )

        # Assign all access attribute to this admin user.
        for choice in AccessAttribute:
            AccountAccess.objects.create(
                account=account,
                access_attribute=choice.value
            )
            
        ServiceLog.objects.create(
            content=f"Created default {username} created with uuid {account.id}.",
            severity=LogSeverity.LOG
        )

    return