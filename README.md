# check_onVirusTotal.ps1
Small script which checks the File Hash and/or File on VirusTotal, can be integrated into the context menu of the windows explorer

You need to have a VT Account:
https://support.virustotal.com/hc/en-us/articles/115002088769-Please-give-me-an-API-key
and **get you API Key, enter your personal key into the $APIKey Variable in the Script - otherwise it won't work**

Can be used Standalone:\
`.\Check_OnVirusTotal.ps1 -FileToProcess "C:\path\to\your\file.exe"`

The Output looks like this:\
![Unbenannt](https://user-images.githubusercontent.com/76947368/112163531-6866a700-8bed-11eb-8057-1a110e8f0102.PNG)
***


Or if you want to use this skript in the context menu, open Regedit, go to:\
Computer\HKEY_CLASSES_ROOT\*\shell\
Create a Key with the Name of the Script, or any name you like, then add a "command" subkey, finally a REG_SZ with this command:
"C:\Program Files\PowerShell\7\pwsh.exe" -File "C:\path\to\this\skript\check_onVirusTotal.ps1" "%V" 

Here is a pic how it should look like:
![Unbenannt](https://user-images.githubusercontent.com/76947368/112162501-67814580-8bec-11eb-826e-7d7c8dfa5d97.PNG)

Now you can run this script from the context menu:
![Unbenannt](https://user-images.githubusercontent.com/76947368/112162607-7e279c80-8bec-11eb-9cbc-722d7c094d93.PNG)

