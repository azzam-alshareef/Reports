# Basics-Windows-Threat-Hutning
# Windows Threat Hunting
Threat hunting on endpoints running a Windows operating system is a complicated task, as there are many moving parts and places adversaries can hide at. This report outlines some of topics, resources and considerations, which aids in threat hunting on Windows endpoints. This report will be going through behavioural analysis which encompasses common legitimate process that malicious software masquerades as, windows logon process, National Software Reference Library (NSRL) and living of the land technique and LOLBAS framework.
# Behavioural Analysis 
Behavioural Analysis is the backbone of threat hunting and security monitoring that leads to building a hypothesis to start hunting. With the increasing cyber threats and evolving techniques such as DLL injection and masquerading processes, traditional signature-based detection is simply not enough. In order to understand abnormal behaviour, one must know what is considered as normal legitimate process.
# Common Legitimate Processes 
System Idle Process PID(0) , System PID(4) : these processes are kernel level processes and the parent of all processes after that. The first process created when starting up a Windows machine is process “System Idle Process” which has a process ID of 0. A child process is then created named "System" with an ID of 4.

<p align="center">
<img src="https://user-images.githubusercontent.com/78951224/148023666-cee63924-3a94-4186-acd0-4524d80e02c1.png")

</p>

Client Server Runtime Subsystem (csrss.exe): is a vital windows process that supports the entire GUI in addition to other low-level windows functions. The legitimate csrss.exe resides at %SystemRoot%\System32\ and the processes cannot be killed or terminated by normal users. The termination of this process will shut down the machine or cause it to be in an unusable state.
<p align="center">
<img src="https://user-images.githubusercontent.com/78951224/148017580-d64b8ca8-7cd3-4373-9e1f-45e0f9b3dfb5.png"/>
</p>

WININIT (wininit.exe): WININIT is another critical process that manages drivers, services in addition to recording mouse and keyboard inputs. wininit.exe cannot be terminated by normal users. If terminated, it will result in restarting the system. WININT should have only one instance running as a process and its binary resides in C:\Windows\System32\.
<p align="center">
<img src="https://user-images.githubusercontent.com/78951224/148017673-1dd5e265-2ec5-44f9-9950-790efcc11c11.png"
 </p>
  
Services.exe: Malwares commonly masquerade as this process. Services.exe is known as Services and controller app. The use of Services.exe is to manage the starting and ending of services. Services.exe resides in C:\Windows\System32. Services.exe has one or more child processes named as “svchost.exe”.
<p align="center">
<img src="https://user-images.githubusercontent.com/78951224/148017749-edebc34b-50f6-42f0-8e86-99cccff18964.png"
</p>
<p align="center">
<img src="https://user-images.githubusercontent.com/78951224/148017756-48da16f6-dd0b-40ed-94e8-37c6e13bea78.png"
   </p>
  
Local Security Authority Subsystem (lsass.exe): Authentication and authorization are key goals of lsass.exe process that reside in C:\Windows\System32. lsass.exe deals with and calls three critical Dynamic library links (DLL’S).
1.	VaultSvc.dll : Credential manager provides a secure storage and retrieval of credentials for users and application and security packages.  
2.	Efssvc.dll : Encrypted file system (EFS) that is the central storage for NTFS encrypted disks. EFS carry an additional layer of security for files and directories.
3.	Samsrv.dll : Security Account Manager holds a list of all users created and security descriptors on the local machine.

<p align="center">
  <img src="https://user-images.githubusercontent.com/78951224/148017816-81ddcaba-7307-4449-8b3f-a51add365a39.png"
</p>
  
Userinit (userinit.exe): Plays a key role in the logon sequence. It handles executing the logon scripts, establishes network connection, then it starts Explorer.exe. Its binary resides in C:\Windows\System32. The registry key "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit" contains the default location of userinit.exe. Wininit.exe is the parent process of userinit.exe and is responsible for launching it.

  <p align="center">
<img src="https://user-images.githubusercontent.com/78951224/148017841-9c0f807a-48c6-4de6-a61f-1972a4d6b968.png"
</p>

Explorer.exe: a GUI shell launched by the user rather than SYSTEM. Explorer.exe is responsible for file manager, desktop, start menu and taskbar. Explorer.exe binary resides in C:\Windows. This is another common name that malware masquerades as. Explorer.exe should be the parent process of all processes initiated by normally logged on users. 

<p align="center">
<img src="https://user-images.githubusercontent.com/78951224/148017880-f795fc34-97f8-4a13-9803-7a7b6d61218f.png"
</p>    
  
Winlogon (winlogon.exe):  Winlogon oversees and manages access to user desktop. In addition, it performs various vital tasks that relate to the windows logon process. 

<p align="center">
<img src="https://user-images.githubusercontent.com/78951224/148017910-310e2df3-baa2-4292-b3b1-897a25db8221.png"
</p>  

# Windows Logon Process
The majority of processes mentioned above are directly or indirectly related to Windows logon process. To break down the windows logon process, LogonUI.exe provides logon interface for users to enter their Username and Password or any other logon mechanism such as PIN or Biometric. WinLogon.exe will pass the credentials to the local security authority subsystem service (lsass.exe). The Authentication Package is a set of DLLs that can be called based on what kind of authentication is required. For example, if Active Directory logon was required Netlogon.dll is used as an authentication package. Alternatively, if the logon hash stored in locally in the Security Account Manager (SAM) database Msv1_0.dll is used instead. On successful logon, winlogon.exe will load the profile and registries in addition to running userinit.exe to display the desktop UI. If the logon attempt failed, a prompt to retry the logon attempt will be displayed until account gets locked out based on the organization’s policy.

<p align="center">
<img src="https://user-images.githubusercontent.com/78951224/148017935-da4d2628-73ec-4212-9d30-73a1c2c1c114.png"
</p>  

# National Software Reference Library (NSRL)  
NSRL by National Institute of Standard and Technology (NIST) provides a database with known good and bad binary hashes that can be used to identify whether a binary is legitimate or malicious. Utilizing the database helps threat hunters to conduct integrity checks on the binaries or scripts in the environment. The following PowerShell command can be used to get the file hash of the any file. 

<p align="center">
<code>C:\Windows\System32> Get-FileHash <File-Name> -Algorithm SHA1</code>
  </p>
The following screenshot shows the above-mentioned command being used on wininit.exe.
  
<p align="center">
<img src="https://user-images.githubusercontent.com/78951224/148018107-90ab4cf2-5e99-460e-90a3-e89ba6b89d70.png"
</p>  

With the resulting SHA1 hash output, threat hunters can make use of  NSRL or equivalent websites such as  Virustotal to compare the hash and determine if the integrity of the file has been affected. It is also important to note that this does not mean that the legitimate file cannot be abused by adversaries.
  
With the resulting SHA1 hash output, threat hunters can make use of  NSRL or equivalent websites such as  Virustotal to compare the hash and determine if the integrity of the file has been affected. It is also important to note that this does not mean that the legitimate file cannot be abused by adversaries.
  
# Living Off The Land Binaries, Scripts and Libraries (LOLBAS) 
Living of the land (LotL) is an attack technique that employs native tools of the environment to perform malicious activities. Adversaries use LotL to avoid detection. Intrusion Prevention Systems make use of signature-based approach that detects and stops malicious processes. By utilizing LotL, adversaries can fly under the radar bypassing signature-based checks as they are using trusted software or processes by the environment mixing it up with regular tasks. LOLBAS provides a list of binaries and scripts that are being utilized by APTs to perform various malicious activities. LOLBAS is classified based on the binary name that adversaries can employ, function the binary could be utilized to perform, and the type of the binary. 
  
<p align="center">
<img src="https://user-images.githubusercontent.com/78951224/148018263-ec8d8b28-55a9-473b-9660-05570e85e45c.png"
</p>  
  
Adversaries can employ the binaries provided by LOLBAS to perform various functions whether its executing commands or uploading and downloading files. At a first glance seeing the binary seems unsuspicious and normal as it’s a trusted software and is expected to run, however, taking a further look and investigating the command lines might result in seeing abnormal commands. Therefore, it is extremely critical that threat hunters take a deeper look at command lines to effectively detect this type of technique and to avoid whitelisting a true positive.
