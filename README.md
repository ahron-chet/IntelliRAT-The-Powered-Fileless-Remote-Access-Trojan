# Fileless AI RAT Exploiting Microsoft Teams Vulnerability

### Overview
This RAT effectively evades Endpoint Detection and Response (EDR) solutions by leveraging fileless and LOLBAS techniques to gain complete control over the target system through privilege escalation. The software exploits a weakness in Microsoft Teams with a DLL reflective attack. The server is capable of managing multiple clients, making it a significant threat. The program is equipped with AI capabilities, including integration with an unlimited version of CHAT GPT, allowing the reverse shell to translate text into commands.

### Key Features
- Memory optimization using fileless and LOLBAS techniques
- Effective bypass of EDR solutions
- Complete system control through privilege escalation
- Data exfiltration through stenography
- DLL reflective attack exploiting a vulnerability in Microsoft Teams
- Secure sessions with RSA stream key exchange and AES encryption
- Ability to steal browser, Wi-Fi, and Windows credentials through LSASS and SAM dump
- Equipped with ransomware capabilities
- Keystroke logging functionality
- Process hollowing while stealing web browser passwords

### Technical Capabilities
The RAT establishes a secure session with RSA stream key exchange and AES encryption before proceeding to steal passwords, including browser and Windows credentials, by dumping the LSASS and SAM processes. The program uses process hollowing techniques to steal web browser passwords and includes keystroke logging and ransomware capabilities. The reverse shell can seamlessly translate text into commands with the integration of an unlimited version of CHAT GPT. The server is capable of managing multiple clients efficiently, making it a formidable threat.
