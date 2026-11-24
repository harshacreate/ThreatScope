ThreatScope demo scripts

75-second demo draft

This is a draft. No video has been recorded yet.

Before recording, start the app:

    docker compose up --build -d

The first start downloads the OWASP ZAP image, which is about 1.5 GB. Do this before the demo. Open http://localhost:8103 and check that the dashboard is ready.

Time: 0:00 to 0:15; Show: Show the start command, the dashboard, and its status.; Say: “ThreatScope is a local practice app for checking security alerts. The sample events are made up, and the scan tools stay on the private demo network.”

Time: 0:15 to 0:35; Show: Open a brute-force alert. Show its proof and response guide.; Say: “Eight failed logins from one source in 120 seconds cause this T1110 alert. The proof shows why it appeared. The guide gives the analyst a next step.”

Time: 0:35 to 0:58; Show: Open Detection Quality. Run the test and show the right alerts, wrong alerts, and missed alerts for each rule.; Say: “This test runs made-up attack events with sample background noise 25 times. Across the rules, it found 150 attacks, with no wrong alerts and no missed attacks.”

Time: 0:58 to 1:15; Show: Show the results for each rule and the note about the test limits.; Say: “These perfect results only apply to the simple sample cases the rules were made for. They give us a clear starting point. They do not show how the rules would work on real attacks or other data.”

Full demo (7 minutes)

Start with `docker compose up --build -d`. ZAP may take a minute to start. Open http://localhost:8103 and check the status message.

Time: 0:00; Do: Show the overview.; Say: “This local lab has 918 made-up events from four sources. It shows six alerts linked to five MITRE ATT&CK methods.”

Time: 0:45; Do: Open the critical data theft alert.; Say: “First, look at the proof. Then look at the response guide. It follows the NIST steps for handling an incident.”

Time: 1:30; Do: Set the brute-force limit to 20 and run the test.; Say: “The attack with 16 failed logins no longer causes an alert. The limit controls how many events are needed.”

Time: 2:15; Do: Show the packet check.; Say: “TShark and Suricata check a saved network file with 62 packets. Suricata found 3 possible attacks.”

Time: 3:00; Do: Run Nmap, then ZAP.; Say: “The target is set in the code, and this lab network cannot reach the internet. It cannot scan other targets. ZAP found 16 missing or weak security headers on the demo site. These are the headers the dashboard sets.”

Time: 4:30; Do: Open Detection Quality and run the test.; Say: “The test uses 25 sets of new sample noise. It found 150 attacks with no wrong alerts. In these samples, a brute-force limit from 3 to 16 works.”

Time: 5:45; Do: Mention sign-in and safety limits.; Say: “The app can use an access token. It also records actions, limits requests, and sets a Content Security Policy to control what the page can load.”

Time: 6:30; Do: Close.; Say: “Alert rules need tests, just like other code. What questions do you have?”
