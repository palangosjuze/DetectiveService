# DetectiveService
A tool for blue teams to detect windows service persistence, that was hidden using restrictive DACL's.

This technique is nicely documented at SANS blog: https://www.sans.org/blog/red-team-tactics-hiding-windows-services

Attackers can hide service persistance using restrictive DACL's using ```sdset``` command. Then the malicious service is not displayed using ```sc query``` or ```sc qc``` commands. And you are also unable to stop the malicious services. You also need to find the hidden services name in order to restore original DACL. For this you can use DetectiveService tool to help you track those sneeky services.

How it works (quite simple):
It compares what you see using ```sc query``` with that registry keys are pressent in ```SYSTEM\CurrentControlSet\Services```. It tries its best to filter out the noise (drivers, service templates etc.).
