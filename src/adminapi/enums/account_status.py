from django.db import models

class AccountStatus(models.TextChoices):
    OK = 'OK', 'Ok'
    DEACTIVATED = 'DEACTIVATED', 'Deactivated'