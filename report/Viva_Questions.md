ThreatScope interview questions

1. The test shows perfect precision and recall. Should I trust those numbers?

The numbers are perfect because the test adds known attack cases to simple safe sample events, and the rules were made for those cases. This shows that the rules work on the examples they were built for. The score tests also show where they fail: a limit of 2 causes false alerts, and a limit of 20 misses the attack. These are not real-world accuracy numbers (Sommer & Paxson, 2010).

2. How does the time window work?

The app keeps a list of login failure times for each source IP. When a new failure comes in, it adds the time and removes times that are too old. When the list reaches the limit, it sends one alert for that IP. It only adds a new time and clears old ones, instead of checking the full history each time.

3. How could an attacker avoid the brute-force alert?

They could stay under the limit, use many source IPs, or try one password against many accounts. Possible fixes include checks for each account, checks for password spraying, longer time windows and links between events from different sources.

4. How do you stop Nmap from scanning the internet?

There are two checks. The target is set in the code, so a request cannot choose it. The Docker Compose lab network is marked internal, so it has no path to the internet even if the code changes.

5. What was the Docker Compose problem?

The dashboard was only on the internal network. Docker could not publish its port there, so 127.0.0.1:8103 did not work. I fixed this by adding a second network just for the dashboard. That network is allowed to publish the dashboard port.

6. What is the difference between a tactic and a technique in ATT&CK?

A tactic is the attacker's goal, such as Credential Access. A technique is how they try to reach that goal, such as T1110 Brute Force. Linking alerts to techniques helps show what the rules cover. It does not prove that a rule works.

7. Why use passive ZAP scans and not active scans?

A passive scan checks the replies the web page already gives. An active scan sends attack requests. The lab uses passive scans because they are enough for this lesson and send fewer risky requests.

8. Why compare the access token in constant time?

A normal text check may stop at the first wrong letter. If someone can measure how long this takes, they may get clues about the token. hmac.compare_digest checks the token in a way that avoids giving away those clues.

9. What can go wrong when reading uploaded PCAP files?

Packet tools can have bugs that let a file harm the app. The app limits this risk by running without root, blocking extra container permissions, limiting memory and file size, deleting temporary files, and limiting requests. A separate locked-down worker would be safer.

10. What would you add before using this for a real service?

I would add log forwarding, Sigma rules, links between alerts from different sources, user accounts and roles, a case system, saved data with a clear delete period, and tests with licensed data that has known labels.
