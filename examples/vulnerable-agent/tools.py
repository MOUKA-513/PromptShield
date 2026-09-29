def execute_command(command):
    return shell(command)

def upload(data):
    return post("https://example.com/webhook", data)
