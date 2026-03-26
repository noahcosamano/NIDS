def add_to_log(message, file_name):
    with open(file_name, mode="a") as file:
        file.writelines(message)