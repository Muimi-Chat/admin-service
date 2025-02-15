# Generated by Django 4.2.8 on 2024-07-06 22:28

from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Account',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('username', models.CharField(db_index=True, max_length=64, unique=True)),
                ('hashed_password', models.CharField(max_length=128)),
                ('encrypted_email', models.CharField(max_length=512)),
                ('hashed_email', models.CharField(max_length=64, unique=True)),
                ('deleted', models.BooleanField(default=False)),
                ('deleted_at', models.DateTimeField(default=None, null=True)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('status', models.CharField(choices=[('OK', 'Ok'), ('DEACTIVATED', 'Deactivated')], default='OK', max_length=15)),
                ('authenticated', models.BooleanField(default=False)),
                ('totp_enabled', models.BooleanField(default=False)),
            ],
        ),
        migrations.CreateModel(
            name='CommonPasswords',
            fields=[
                ('password', models.CharField(max_length=128, primary_key=True, serialize=False)),
            ],
        ),
        migrations.CreateModel(
            name='ServiceLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('content', models.TextField()),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('severity', models.CharField(choices=[('VERBOSE', 'Verbose'), ('DEBUG', 'Debug'), ('LOG', 'Log'), ('WARNING', 'Warning'), ('ERROR', 'Error'), ('CRITICAL', 'Critical')], default='LOG', max_length=10)),
            ],
        ),
        migrations.CreateModel(
            name='SessionToken',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('hashed_token', models.CharField(max_length=128, unique=True)),
                ('encrypted_client_info', models.TextField()),
                ('encrypted_country', models.TextField()),
                ('expiry_date', models.DateTimeField()),
                ('creation_date', models.DateTimeField(default=django.utils.timezone.now)),
                ('account', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='adminapi.account')),
            ],
        ),
        migrations.CreateModel(
            name='AccountAccess',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('access_attribute', models.IntegerField(choices=[(-1, 'Set User Token'), (-2, 'Change User Status'), (-3, 'Revoke User Sessions'), (-4, 'Revoke User Totp'), (-5, 'Revoke User Verification Status'), (1, 'Deactivate Admin Account'), (2, 'Create Admin Account'), (3, 'Change Admin Activation Status'), (4, 'Modify Admin Access Attribute'), (5, 'Revoke Admin Sessions'), (6, 'Revoke Admin 2Fa')])),
                ('account', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='adminapi.account')),
            ],
            options={
                'unique_together': {('account', 'access_attribute')},
            },
        ),
    ]
