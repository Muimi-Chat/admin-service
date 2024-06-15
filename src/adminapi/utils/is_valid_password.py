import re
def is_valid_password(password):
    reg = r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d!@#$%^&*()-_=+`~[\]{}\\|;:'\",.<>/?]{8,72}$"
    reg_com = re.compile(reg)
    return re.search(reg_com,password) is not None
