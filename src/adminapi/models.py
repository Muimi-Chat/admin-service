from django.db import models
from django.utils import timezone
import uuid

from .enums.access_attribute import AccessAttribute
from .enums.log_severity import LogSeverity
from .enums.account_status import AccountStatus
from .enums.email_token_purpose import EmailTokenPurpose

class Account(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(max_length=64, unique=True, db_index=True)
    hashed_password = models.CharField(max_length=128)
    encrypted_email = models.CharField(max_length=512)
    hashed_email = models.CharField(max_length=64, unique=True)
    deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(default=None, null=True)
    created_at = models.DateTimeField(default=timezone.now)
    status = models.CharField(max_length=15, choices=AccountStatus.choices, default=AccountStatus.OK)
    # Authenticated if password is changed.
    authenticated = models.BooleanField(default=False)
    totp_enabled = models.BooleanField(default=False)

class AccountAccess(models.Model):
    class Meta:
        unique_together = ['account', 'access_attribute']

    account = models.ForeignKey(Account, on_delete=models.CASCADE)
    access_attribute = models.IntegerField(choices=AccessAttribute.choices)

class SessionToken(models.Model):
    account = models.ForeignKey(Account, on_delete=models.CASCADE)
    hashed_token = models.CharField(max_length=128, unique=True)
    encrypted_client_info = models.TextField()
    encrypted_country = models.TextField()
    expiry_date = models.DateTimeField()
    creation_date = models.DateTimeField(default=timezone.now)

class ServiceLog(models.Model):
    content = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)
    severity = models.CharField(max_length=10, choices=LogSeverity.choices, default=LogSeverity.LOG)

class CommonPasswords(models.Model):
    password = models.CharField(max_length=128, primary_key=True)