# ThreatScope demo scripts

## 75-second demo draft

The script is a draft. No video has been recorded.

Before recording, start the app with:

    docker compose up --build -d

The first start downloads the OWASP ZAP image, about 1.5 GB. Do this before the demo. Open http://localhost:8103 and make sure the dashboard is ready.

| Time | Show | Say |
|---|---|---|
| 0:00–0:15 | Show the start command, then the dashboard and its status. | “ThreatScope is a local lab for testing SOC alerts. The sample events are made up, and the scan tools stay on the private demo network.” |
| 0:15–0:35 | Open a brute-force alert. Show its proof and response guide. | “Eight failed logins from one source in 120 seconds cause this T1110 alert. The proof shows why it fired. The guide gives the analyst a next step.” |
| 0:35–0:58 | Open Detection Quality. Run the test and show the true, false and missed alert counts for each rule. | “This test runs made-up attack events with sample background noise 25 times. The README reports 150 true alerts, no false alerts and no missed alerts across the rules.” |
| 0:58–1:15 | Show results for each rule and the note about limits. | “These perfect results only apply to the simple sample cases the rules were made for. They give us a repeatable starting point. They do not show real-world accuracy or results on outside data.” |

## Full demo (7 minutes)

Start with docker compose up --build -d. ZAP may take a minute to start. Open http://localhost:8103 and check the status message.

| Time | Do | Say |
|---|---|---|
| 0:00 | Show the overview. | “This is a local SOC lab. It has 918 made-up events from four sources and six alerts linked to five ATT&CK techniques.” |
| 0:45 | Open the critical data theft alert. | “First, look at the proof. Then look at the response guide, which follows the NIST incident response steps.” |
| 1:30 | Set the brute-force limit to 20 and run the test. | “The attack with 16 failed logins no longer triggers an alert. The limit controls which events cause an alert.” |
| 2:15 | Show the packet check. | “TShark and Suricata check a packet capture file: 62 packets and 3 IDS alerts.” |
| 3:00 | Run Nmap, then ZAP. | “The target is set in the code, and the lab network cannot reach the internet. It cannot scan other targets. ZAP found 16 security header issues on the demo target. These are the headers the dashboard sets.” |
| 4:30 | Open Detection Quality and run the test. | “The test uses 25 sets of fresh sample noise. It found 150 true alerts and no false alerts. The results show that a brute-force limit from 3 to 16 works for these samples.” |
| 5:45 | Mention sign-in and safety limits. | “The app can use an access token, logs actions, limits requests and sets a Content Security Policy.” |
| 6:30 | Close. | “Alert rules need tests and measurements, like other code. What questions do you have?” |
