# Filless AI RAT using Microsoft Teams Vulnerability

### Introduction
This program was designed to minimize memory footprint and bypass existing Endpoint Detection and Response (EDR) solutions. The program grants complete control over a system by applying privilege escalation and utilizes cryptography to pull relevant information from the internet. The software runs under the "Nt authority user" system and uses a DLL reflective attack against Teams.exe, exploiting a security vulnerability in Microsoft Teams.

### Key Features
- Memory optimization for stealthiness
- Bypasses existing EDR solutions
- Complete control over the system through privilege escalation
- Utilizes cryptography to pull relevant information from the internet
- DLL reflective attack against Teams.exe
- Exploits a security vulnerability in Microsoft Teams
- Full implementation of the RSA algorithm in PowerShell and Python, including various matching algorithmsת
RSA stream key exchange at the start of each session
AES encryption with added security enhancements
- Ability to steal passwords of browsers, Wi-Fi, and Windows credentials through LSASS and SAM dump
- Integration with an unlimited version of CHAT GPT, allowing the reverse shell to convert textual descriptions into functional commands.

### Technical Details
The software starts by performing a stream key exchange with the RSA algorithm between the target and server. The session is then encrypted with AES, with added security enhancements. The system control provides the ability to steal passwords, including browser and Windows credentials, by performing a dump of the LSASS and SAM processes.

### Conclusion
This AI RAT software takes advantage of a security vulnerability in Microsoft Teams to grant complete control over a system, while minimizing its memory footprint and bypassing existing EDR solutions. The program integrates with an unlimited version of CHAT GPT, allowing the reverse shell to convert textual descriptions into functional commands.
