from django.db import models

class EmailTokenPurpose(models.TextChoices):
    VERIFY = 'VERIFY', 'VERIFY'
    PASSWORD_RESET = 'PASSWORD_RESET', 'PASSWORD_RESET'