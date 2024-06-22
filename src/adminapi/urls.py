from django.urls import path

from . import routers
from . import totp_routers
from . import user_routers
from . import forgot_password_routers

from . import register_admin_routers
from . import control_admin_access_routers
from . import view_logs_routers
from . import view_users_routers

from . import manage_users_router

urlpatterns = [
    path("login", routers.login, name="login"),
    path('csrf_token/', routers.request_registration_csrf, name='get_csrf_token'),
    path("service-user-info/", routers.get_user_info, name="service_get_user_information"),

    path("enable-totp/", totp_routers.enable_totp, name="enable_totp"),
    path("confirm-totp/", totp_routers.confirm_totp, name="confirm_totp"),
    path("disable-totp/", totp_routers.disable_totp, name="disable_totp"),

    path("request-user-info/", user_routers.request_user_info, name="request_user_info"),
    path("change-email/", user_routers.change_email, name="change_email"),
    path("change-password/", user_routers.change_password, name="change_password"),
    path("confirm-email-change/", user_routers.confirm_email_change, name="confirm_email_change"),
    path("revoke-session/", user_routers.revoke_session, name="revoke_session"),

    path("reset-password/", forgot_password_routers.send_forgot_password_email, name="reset_password"),
    path("confirm-password-reset/", forgot_password_routers.confirm_password_reset, name="confirm_password_reset"),
    
    path("view-logs/", view_logs_routers.view_logs, name="view_logs"),

    path("register-admin/", register_admin_routers.register_new_admin, name="register_admin"),
    path("control-admin-access/", control_admin_access_routers.control_admin_access, name="control_admin_access"),

    path("view-users/", view_users_routers.view_users, name="view_users"),
    path("revoke-user-totp/", manage_users_router.remove_user_totp, name="revoke_user_totp"),
    path("remove-user-verification/", manage_users_router.remove_user_verification, name="remove_user_verification"),
    path("set-user-status/", manage_users_router.change_user_status, name="set_user_status"),
]