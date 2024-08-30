<h1>Computer Forensics - Memory Analysis</h1>

<h3>Objective</h3>
The aim of this project is to analyze an image and answer several questions.
<br /> <br />
<h3>Skills Learned</h3>
● Volatility tool <br />

<br />
<h3>Tools Used</h3>
● Volatility <br />
● VirusTotal <br />
● Kali Linux <br />
<br />
<h3>Steps</h3>
QUESTION 1 <br />
What profile is the most appropriate for this machine? (ex: Win10x86_14393) <br />
To see the profile of the machine we used the following command: <br />
"python2.7 vol.py imageinfo -f adam.mem"  <br />
<img width="732" alt="memory1" src="https://github.com/user-attachments/assets/cd8f3a24-8bff-4ee1-a55a-411730867028">
<br />
*Ref 1: Volatility imageinfo command*
<br />
Answer: The most appropriate would be Win7SP0x64 or Win7SP1x64, a Windows 7 machine.
<br />
<br />
QUESTION 2 <br />
What was the process ID of notepad.exe? <br />
We run the command pstree in order to see the pid of the process. To filter just the notepad.exe, we use the following command:
<br />
"python2.7 vol.py -f /home/kali/Downloads/adam.mem --profile=Win7SP0x64 pstree | grep notepad.exe"  <br />
<img width="735" alt="memory2" src="https://github.com/user-attachments/assets/48bb5fba-168b-497f-9b7c-1f9c9bf96250">
<br />
*Ref 2: Volatility pstree command*
<br />
Answer: The pid of the process is 3032.
<br />
<br />
QUESTION 3 <br />
Name the child processes of wscript.exe. <br />
Using the same command as in the previous question, we can see that the process wscript.exe has pid=5116. Then, we used the following command to see if any other process had 5116 as ppid:
<br />
"python2.6 vol.py -f /home/kali/Downloads/adam.mem --profile=Win7SP1x64 pstree | grep 5116"  <br />
<img width="733" alt="memory3" src="https://github.com/user-attachments/assets/7121eac7-1db1-4d21-baae-22364e210c9a">
<br />
*Ref 3: Volatility pstree command*
<br />
Answer: Its child process is 0xfffffa8005a1d9e0:UWkpjFjDzM.exe, with pid=3496 and ppid=5116 of the wscript.exe process.
<br />
<br />
QUESTION 4 <br />
What was the IP address of the machine at the time the RAM dump was created?
<br />
To determine the IP address we used the netscan command to examine the network connections:
<br />
"python2.7 vol.py -f /home/kali/Downloads/adam.mem --profile=Win7SP1x64 netscan"  <br />
<img width="514" alt="memory4" src="https://github.com/user-attachments/assets/ebc3a2a1-7837-4e4b-87d3-825c6b828c55">
<br />
*Ref 4.1: Volatility netscan command*
<br />
As all connections are displayed, we used the grep command option to filter out IPv6 connections, as well as the addresses 0.0.0.0. and 127.0.0.1.
<br />
"python2.7 vol.py -f /home/kali/Downloads/adam.mem --profile=Win7SP1x64 netscan | grep v4 | egrep -v '0.0.0.0|127.0.0.1'"
<br />
<img width="514" alt="memory4 1" src="https://github.com/user-attachments/assets/5ba189a4-bbd8-4bb5-adfd-e7f8516c8093">
<br />
*Ref 4.2: Volatility netscan command*
<br />
Answer: Under local addresses is the IP address of the machine: 10.0.0.101.
<br />
<br />
QUESTION 5 <br />
Based on the answer regarding to the infected PID, can you determine what the IP of the attacker was?
 <br />
To know which is the infected process, we run this command to get info about the processes and applications that are being run:
<br />
"python2.7 vol.py -f /home/kali/Downloads/adam.mem --profile=Win7SP0x64 pstree"  <br />
<img width="515" alt="memory5" src="https://github.com/user-attachments/assets/e9fd9a8f-6edc-4aed-95c5-a6a82e4905d0">
<br />
*Ref 5.1: Volatility pstree command*
<br />
With all the list of processes running, we focus one the ones that don’t seem legitimate, such as:
<br />
● 0xfffffa8005a1d9e0:UWkpjFjDzM.exe: seems to be the infected process, due to the weird name and that the rest seem to be legitimate.
<br />
   ○ Pid: 3496
  <br />
To get the associated IP address of the process, we used this command:
<br />
"python2.7 vol.py -f /home/kali/Downloads/adam.mem --profile=Win7SP0x64 netscan | grep 3496"
<br />
<img width="515" alt="memory6" src="https://github.com/user-attachments/assets/4850e8c9-6589-4789-828e-6eb1553a859f">
<br />
*Ref 5.2: Volatility netscan command*
<br />
Answer: The IP of the attacker is 10.0.0.101:49217
<br />
<br />
QUESTION 6 <br />
What process name is VCRUNTIME140.dll associated with? <br />
To display the list of dlls of each process we use the dlllist option:<br />
"python2.7 vol.py -f /home/kali/Downloads/adam.mem --profile=Win7SP0x64 dlllist"  <br />
As all dlls are displayed, we filter the results fit the following command: <br />
"python2.7 vol.py -f /home/kali/Downloads/adam.mem --profile=Win7SP0x64 dlllist | grep VCRUNTIME140.dll"  <br />
<img width="517" alt="memory6 1" src="https://github.com/user-attachments/assets/76ca31f7-3120-472a-b07e-0d8a0f5eca25">
<br />
*Ref 6: Volatility dlllist command*
<br />
Answer: The associated processes as can be observed in the image, are ClickToRun and Office16.
<br />
<br />
QUESTION 7 <br />
What is the md5 hash value of the potential malware on the system?
<br />
First we used the procdump command to dump the infected process using its pid:
<br />
"python2.7 vol.py -f /home/kali/Downloads/adam.mem --profile=Win7SP0x64 procdump -D. -p 3496"
<br />
<img width="511" alt="memory7 1" src="https://github.com/user-attachments/assets/b2e98c1c-cc2e-425f-9b41-0011fa4eb092">
<br />
*Ref 7.1: Volatility procdump command*
<br />
Once we have the process dumped, we can get the MD5 hash of that file:
<br />
"md5sum executable.3496.exe"
<br />
<img width="368" alt="memory7 2" src="https://github.com/user-attachments/assets/8fe26e01-82a3-4807-9397-f8000a8572d0">
<br />
*Ref 7.2: Mdsum command*
<br />
Answer: The hash is 690ea20bc3bdfb328e23005d9a80c290.
<br />
When searching this hash in VirusTotal, it is defined as malicious.
<br />
<img width="512" alt="memory7 3" src="https://github.com/user-attachments/assets/f2d7c38a-239e-4a5b-b479-0af0f3473fe1">
<br />
*Ref 7.2: VirusTotal hash*
<br />
<br />
QUESTION 8 <br />
An application was run at 2019-03-07 23:06:58 UTC, what is the name of the program?
<br />
We downloaded the “shimcachemem” plugin to parse the executable information. To filter the results of the given date, we used the grep option.
<br />
"python2.7 vol.py -f /home/kali/Downloads/adam.mem --profile=Win7SP0x64 shimcachemem | grep "2019-03-07 23:06:58""  
<br />
<img width="514" alt="memory8" src="https://github.com/user-attachments/assets/a89ca4b0-31d4-4aab-a005-0d8d654854d7">
<br />
*Ref 8: Volatility plugin “shimcachemem”*
<br />
Answer: The program is Skype.
<br />
<br />
QUESTION 9 <br />
What is the shortname of the file at file record 59045?
<br />
We used the mftparser command as it displays the Master File Table entries information. To get just the record number 59045 we filtered the results using grep:
<br />
"python2.7 vol.py -f /home/kali/Downloads/adam.mem --profile=Win7SP0x64 mftparser | grep -C 15 '59045'"<br />
<img width="512" alt="memory9" src="https://github.com/user-attachments/assets/8edaf364-8e36-49f9-a82f-309161e68728">

<br />
*Ref 9: Volatility mftparser command*
<br />
Answer: The short name is “EMPLOY-1.XLS".
<br />
<br />
QUESTION 10 <br />
This box was exploited and is running meterpreter. What PID was infected?
<br />
When searching the hash of question 7, we found out that it corresponds to meterpreter malware.
<br />
<img width="515" alt="memory10" src="https://github.com/user-attachments/assets/40ef962c-3294-40d5-b361-a788d473a9db">
<br />
*Ref 10: VirusTotal meterpreter*
<br />
Answer: UWkpjFjDzM.exe PID is 3496, as stated in question 5.
<br />
<br />
