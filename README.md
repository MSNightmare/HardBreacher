# HardBreacher
Kaspersky Antivirus For Endpoint ZeroDay Elevation of Privileges Vulnerability

So the problem is now leaking outside of Microsoft, there was poll held against either finding a bug in the home or commercial version and the poll results were the commercial version.
At the time of writing this, the proof of concept works in a fully patched windows 11 25H2 & Kaspersky for Endpoint v14.0.0.504
The PoC is not in the best shape at all, it is basically duct tapped, I just managed to make it work and that's all. It will fail to run with error so you just have to keep rerunning it. If it succeeds, it will create a file in C:\Windows\System32\MY_SNAKE_IS_SOLID.dll will full permissions for current user.
The interesting part about this is the Kaspersky completely loses it when you take control over the UI process, you can cause it to stop functioning, grant/block access to files its not supposed to, if the PoC succeeds, the entire operating system becomes a hot mess.

Anyways, here is a useless screenshot about where I tested it and it worked (after a reboot)
<img width="1799" height="699" alt="Untitled" src="https://github.com/user-attachments/assets/bfc43dee-7e07-4206-95bd-402e03af5812" />

Regardless, I still think this can be turned into a stable silent one click exploit, I just don't have the time and resources to do it.
