import openai

class AiHelp(object):
    
    def __init__(self,apikey):
        openai.api_key = apikey


    def translateToCommand(self,command):
        confirm = False
        if command[-13:]=="--autoconfirm":
            confirm = True
            command = command[:-13]
        response = openai.Completion.create(
        model="text-davinci-003",
        prompt=f"Convert this text to a programmatic command in powershell: {command}",
        temperature=0,
        max_tokens=1000
        )
        command = response["choices"][0]["text"].strip().replace('Write-Host ','echo ')
        if confirm:
            return command
        while True:
            ask = input(f"{command}\n\ny/n: ")
            if ask == "y":
                return command
            elif ask == "n":
                return False