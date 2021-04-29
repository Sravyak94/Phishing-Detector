# Phishing Detector
Initially three machine learning algorithms are trained to compare the accuracy of the results by using a dataset consisting of 30 URL specific features and around 11000 data points. This data-set is taken from machine learning repository. Based on final results, Random Forest Model is found to be the best among them with the highest accuracy of 97.5 percent. By making use of client-server architecture, URL is sent in the request from the client to the server through restful API calls using web browser extension. At the back end, features are extracted from the URL. The extracted features are then sent to the trained Random Forest Classifier model and finally the model will predict if entered URL is Legitimate/Phishing and return the response to the Client. The phishing websites are considered from PhishBank blog website. 
The most common features particularly implemented in this project to check whether a URL is valid or not are as follows:
1. IP Address: To check whether IP Address is present in domain name of URL.
2. URL Length: To check for the length of the URL. If it is more than 75 characters, then classifying it as PhishingWebsite else if its less than 54 characters then classifying it as Legitimate Website.
3. Shortening Service: If its a tiny URL then identified as Phishing otherwise Legitimate.
4. Having '@' symbol: If URL contains '@' symbol then Phishing else Legitimate.
5. Redirecting using '//': If position of last occurrence of '//' is more than 7 then Phishing otherwise Legitimate.
6. Prefix/Suffix: If domain name includes '-' then Phishing else Legitimate.
7. Sub Domain and Multi Sub Domains: If dots are present in domain part 1 then Legitimate and if they are present in domain part 2 then Suspicious otherwise Phishing.
8. SSL Final State: If the URL uses https and age of certificate is more than an year then Legitimate otherwise Phishing.
9. Domain Registration Length: If domain expires in less than an year then Phishing else Legitimate.
10. Favicon Check: A favicon is a graphic image (icon) associated with a specific webpage. If Favicon loaded from external domain then Phishing else Legitimate.
11. Port Status: If all ports are open, phishers can run almost any service they want and as a result, user information is threatened. So if port is not in the preferred status then its Phishing else Legitimate.
12. HTTPS Token: If http token is used in domain part of URL then Phishing else Legitimate.
13. Request URL: If the external objects present in webpage is less than 22 percent then it is Legitimate but if its more than 61 percent then it is Phishing.
14. URL of Anchor: The anchor <a> tags and websites have different domain names. Anchor might not link to any webpage. If such anchor tags are less than 31 percent it is Legitimate. If it is more than 67 percent then Phishing.
15. Link in tags: Link tags are used to retrieve other web resources. If the percentage of Links is less than 17 then Legitimate and if its more
than 81 then Phishing.
16. Server Form Handler: SFHs that contain an empty string or \about:blank" are considered doubtful because an action should be taken upon the submitted information. Hence if they are blank or empty then Phishing, referring to a different domain then Suspicious else Legitimate.
17. Submitting Information to Email: If Client or Server side mail() or mailto functions are used to submit user information then its Phishing else Legitimate.
18. Abnormal URL: If host name is not included in URL then Phishing else Legitimate.
19. iFrame: It is a html tag to display a webpage within a webpage. The tag will be made invisible by Phishers. If iFrames are used then Phishing else Legitimate.
20. Age of Domain: Most of the Phishing websites live for short duration. Hence if the age of domain is more than 6 months it is Legitimate otherwise it is Phishing.
21. DNS Record: DNS Record is used to map a URL to an IP Address using database. If the DNS record is empty or not found then the
website is classified as Phishing, otherwise it is classified as Legitimate.
22. Website Traffic: The feature is used to measure the popularity of a website using number of visitors and number of pages being visited. If the website rank is below 100,000 then Legitimate else it is Phishing.
