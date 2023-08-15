# Web-application-fingerprinting-and-XSS-scanner
![image](https://github.com/Madhvesh77/Web-application-fingerprinting-and-XSS-scanner/assets/101399792/7f3bff62-4c16-4c4d-8a76-9da63b4036ed)

WebSentinel is a powerful and comprehensive web application security assessment tool designed to assist security professionals, developers, and penetration testers in identifying potential vulnerabilities in web applications. It provides fingerprinting capabilities, form extraction, and extensive Cross-Site Scripting (XSS) vulnerability testing. By automating these processes, WebSentinel helps enhance the security posture of web applications and prevents potential security breaches.
WebSentinel stands as a robust and reliable tool to assess the security of web applications. Its combination of fingerprinting, form extraction, comprehensive XSS testing, and reporting capabilities empowers security professionals to proactively identify vulnerabilities and enhance the overall security of web applications.
It makes use of a XSS dataset, which contains 13685 samples containing both benign and xss instances. It has more that 7600 instances of XSS instances. 
This tool makes use of those instances which are labelled as XSS input for testing a form. This tool tries each and every instnce in a form and breaks the automation once the web page is vulnerable for atleast 10 instances. the dataset can be downloaded from https://www.kaggle.com/datasets/syedsaqlainhussain/cross-site-scripting-xss-dataset-for-deep-learning?resource=download 
Testinng folder is a test web application which is poweredd by django and contains 2 pages one of which is least secured and the other one is very secure. Thus it can be used to test the tool. 
The following process can be followed to run the tool.
![image](https://github.com/Madhvesh77/Web-application-fingerprinting-and-XSS-scanner/assets/101399792/a3523deb-f150-42a3-916b-2c84087c1c7f)
