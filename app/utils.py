import re 

   # Función para verificar la fortaleza de la contraseña
def password_check(contrasena):
    # Verifica que la contraseña tenga al menos 8 caracteres
    if len(contrasena) < 8:
        return False

    # Verifica que la contraseña contenga al menos una letra minúscula
    if not re.search("[a-z]", contrasena):
        return False

    # Verifica que la contraseña contenga al menos una letra mayúscula
    if not re.search("[A-Z]", contrasena):
        return False

    # Verifica que la contraseña contenga al menos un dígito
    if not re.search("[0-9]", contrasena):
        return False

    # Verifica que la contraseña contenga al menos un carácter especial
    if not re.search("[!@#$%^&*(),.?\":{}|<>]", contrasena):
        return False

    return True