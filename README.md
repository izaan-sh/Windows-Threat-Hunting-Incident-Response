# Windows-Threat-Hunting-Incident-Response

created a resource group and named it RG-IR-Lab

then created a network security group named it NSG-IR-Lab
then added inbound rules to allow rdp and ssh from my device:

<img width="1912" height="827" alt="image" src="https://github.com/user-attachments/assets/f6c4a9e3-91ef-4976-85b9-e7c40eb8d3c5" />



created the log analytics workspace:
<img width="943" height="722" alt="image" src="https://github.com/user-attachments/assets/82a92c27-2ebd-4755-89fb-336b165cd46e" />

created the windows vm: 
<img width="1265" height="615" alt="image" src="https://github.com/user-attachments/assets/0e2ab89e-c4e7-42d9-81aa-5374b517c767" />

created kali vm
<img width="1262" height="607" alt="image" src="https://github.com/user-attachments/assets/194c36c6-8e8d-4d10-9fd7-b63a6dc00a3b" />

both the vms deployed:
<img width="1913" height="756" alt="image" src="https://github.com/user-attachments/assets/7818a8b0-e523-45c5-bde6-a7ff63203512" />


rdp into windows and ssh into kali and then testing connectivity:

<img width="1416" height="779" alt="image" src="https://github.com/user-attachments/assets/9888117a-1f71-447a-a8c5-cb7889499600" />

<img width="1481" height="758" alt="image" src="https://github.com/user-attachments/assets/7df17d4d-0bba-4fe3-8d6a-47493bf0eb16" />

phase 2 : Logging, Sysmon, and connecting to Sentinel

then ran the audit policy commands


windows security events configuration
<img width="1915" height="932" alt="image" src="https://github.com/user-attachments/assets/406a07b3-b20b-41b8-b4a6-bc8c71075ef5" />


creating data collection rule: 

<img width="890" height="925" alt="image" src="https://github.com/user-attachments/assets/3853a506-56d3-4f5a-aaf6-d2661c081c02" />

sysmon running verification:
<img width="1517" height="802" alt="image" src="https://github.com/user-attachments/assets/1f029867-fdf0-4625-9abc-aa0fc4aefcfa" />

sentinel collecting logs:

<img width="1491" height="912" alt="image" src="https://github.com/user-attachments/assets/5963d94a-e698-4b9f-9f1b-2b5f9e79c6a4" />









