from django.db import models

class LogSeverity(models.TextChoices):
    VERBOSE = 'VERBOSE', 'Verbose'
    DEBUG = 'DEBUG', 'Debug'
    LOG = 'LOG', 'Log'
    WARNING = 'WARNING', 'Warning'
    ERROR = 'ERROR', 'Error'
    CRITICAL = 'CRITICAL', 'Critical'