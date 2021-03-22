# check_onVirusTotal
Small script which checks the File Hash and/or File on VirusTotal, can be integrated into the context menu of the windows explorer

If you wand to use this skript in the context menu, open Regedit, go to:
Computer\HKEY_CLASSES_ROOT\*\shell\

"C:\Program Files\PowerShell\7\pwsh.exe" -File "C:\path\to\this\skript\check_onVirusTotal.ps1" "%V" 

Now you can run this script from the context menu:
![pic](https://user-images.githubusercontent.com/76947368/111978345-16962200-8b04-11eb-9c6e-1ea976542964.png)
