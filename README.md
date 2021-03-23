# check_onVirusTotal
Small script which checks the File Hash and/or File on VirusTotal, can be integrated into the context menu of the windows explorer

You need to have a VT Account:
https://support.virustotal.com/hc/en-us/articles/115002088769-Please-give-me-an-API-key
and **get you API Key, enter your personal key into the $APIKey Variable in the Script - otherwise it won't work**

Can be used Standalone:\
`.\Check_OnVirusTotal.ps1 -FileToProcess "C:\path\to\your\file.exe"`

Or if you want to use this skript in the context menu, open Regedit, go to:\
Computer\HKEY_CLASSES_ROOT\*\shell\
Create a Key with the Name of the Script, or any name you like, then add a "command" subkey, finally a REG_SZ with this command:
"C:\Program Files\PowerShell\7\pwsh.exe" -File "C:\path\to\this\skript\check_onVirusTotal.ps1" "%V" 

Here a pic:
![Unbenannt](https://user-images.githubusercontent.com/76947368/111978745-8e644c80-8b04-11eb-9f40-8f94575ca6d4.PNG)

Now you can run this script from the context menu:
![pic](https://user-images.githubusercontent.com/76947368/111978345-16962200-8b04-11eb-9c6e-1ea976542964.png)
