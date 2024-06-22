import re
def is_valid_password(password):
    regex = ("^(?=.*[a-z])(?=." +
            "*[A-Z])(?=.*\\d)" +
            "(?=.*[-+_!@#$%^&*., ?]).+$")
     
    # Compile the ReGex
    reg_com = re.compile(regex)
    return re.search(reg_com,password) is not None
