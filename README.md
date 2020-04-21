# tokenimpersonation
This c code pop's a system shell by stealing a token from a system process called winlogon.exe

The code uses openprocess,openprocesstoken,duplicatetokenex and finally creates a process by calling createprocesswithtokenw and passing the duplicated token.
You need to be running the process as admin after bypassing the UAC prompt.
