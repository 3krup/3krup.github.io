---
title: "My Path to the HTB CDSA Certification: How I Passed and What I Learned"
date: "2025-09-08"
tags:
    - [Certifications]
    - [HTB]
    - [Blue Team]
    - [CDSA]
thumbnail: "https://www.comptia.org/images/default-source/connect-blog-images/red-team-vs-blue-team-what-s-the-difference.jpg?sfvrsn=3c57706_2"
bookmark: true

---

> **Summary:** This post details my personal journey of passing the practical HTB Certified Defensive Security Analyst (CDSA) exam. It covers my preparation strategy, a breakdown of the 7-day exam experience, and essential tips for anyone aspiring to earn this blue team certification.

---

Hello everyone, and welcome to my first-ever blog post! The feeling is incredible, not just because I'm launching this blog, but because I have some exciting news to share – **I have officially passed the Hack The Box Certified Defensive Security Analyst (HTB CDSA) exam!**

The journey was challenging but immensely rewarding. Through this article, I want to share my entire experience, from the moment I decided to pursue it, through the preparation, and all the way to the exam itself. I hope my story will be helpful to all of you who are considering the same path.

#### **Overview**

The HTB CDSA is not your typical multiple-choice certification. It is a completely practical, hands-on exam that places you in the role of a Security Analyst in a realistic scenario. Its goal is to test your skills in security analysis, Security Operations Center (SOC) procedures, and Incident Response.

This certification is designed for those who want to validate their Blue Team skills. If you are interested in roles like SOC Analyst, Incident Responder, Threat Hunter, or Digital Forensics Analyst, then this is the right choice for you. It confirms that you possess intermediate-level technical competence and are capable not only of finding traces of an attack but also of writing a professional report about it.

#### **What is the CDSA and What's the Pricing?**

The HTB CDSA teaches and tests you in the following domains:

- **SIEM Operations** (Splunk and the ELK Stack)
- **Log Analysis** from various sources
- **Threat Hunting** (proactively searching for threats)
- **Network Traffic Analysis** (Wireshark, Suricata/Zeek)
- **Basic Malware Analysis**
- **Digital Forensics and Incident Response (DFIR)**
- **Professional Incident Report Writing**

Regarding the price, there are two components: **the training and the exam itself.**

1.  **Training (HTB Academy):** To be eligible for the exam, you must complete the entire "SOC Analyst" job-role path on the Hack The Box Academy. The most cost-effective option is the **Silver Annual subscription**, which costs **$490 per year**. This plan grants you access to all the necessary modules and includes **one exam voucher** (for the CDSA, CPTS, or CBBH). Monthly subscriptions are also available, but the annual plan is more economical in the long run.
2.  **Exam (Voucher):** If you purchase the exam voucher separately, its price is **$210**.

So, for the complete package (training + exam), the most common investment is $490.

#### **Preparation**

Preparation is the key to everything, and there are no shortcuts. The only real path is to **complete the entire "SOC Analyst" job-role path on HTB Academy**. This path consists of 28 modules (this number may change) that cover everything from the fundamentals to advanced techniques.

My approach to preparation was as follows:

-   **Focused Module Completion:** I didn't just read and click "next." I carefully studied each module and did the hands-on exercises multiple times until I was certain I fully understood the concepts.
-   **Note-Taking:** This is absolutely crucial. I used Obsidian for my notes. For every tool and technique, I wrote down key commands, SIEM queries, and processes. I created my own personal cheat sheet that proved invaluable during the exam.
-   **Understanding the "Why":** It’s not enough to just know a command. I made an effort to understand _why_ I was using a specific Splunk query or _why_ I was looking at a particular log file. Understanding the attacker's perspective greatly helps in defense.
-   **Extra Practice:** Although the Academy is sufficient, I recommend completing a few machines on the main HTB platform and trying some of the Splunk BOTS (Boss of the SOC) scenarios available online. It builds confidence.

#### **The Exam**

The exam itself lasts for **7 days**. When you begin, you are given VPN access and a "Letter of Engagement" that explains your task.

The format is as follows: You are placed in an environment with multiple machines, and your task is to investigate **two separate security incidents**. During your investigation, you will find evidence, analyze logs, network traffic, memory dumps, and files.

The key to passing isn't just the technical analysis. To pass, you must write and submit a **professional, detailed incident report**. This report must contain all your findings, evidence (screenshots), the attack timeline, the tools and SIEM queries you used, and recommendations for remediation. The report carries a massive portion of the final grade.

#### **My Exam Experience**

My 7-day exam felt like a real job as a SOC Analyst. Here’s a breakdown of how it went for me:

On the very first day, I managed to solve 16 out of 20 flags for the first incident. By the second day, I had already met the minimum passing requirement (16/20 flags total) and started writing the report for Incident 1 without waiting.

On the third day, I began working on Incident 2, which was more difficult and required more independent investigation than the first one. In Incident 1, you have a clearer idea of what to look for and in what order, but Incident 2 was a different beast. After spending two days on that incident, I started writing the report for it once all the pieces of the puzzle began to fit together.

In the meantime, I went back and finished Incident 1 completely, ending with 18 out of 20 flags. The final day was dedicated solely to finishing and polishing the report. I made sure to accompany every finding with screenshots.

Throughout the entire process, I took meticulous notes. This turned out to be a very smart decision, as it allowed me to easily verify everything and ensure I didn't forget any details while writing the report. In terms of time commitment, I spent about 5 hours of real, productive work each day. Thanks to my previous experience, I didn't find the certification overly difficult, but my thorough preparation on the HTB Academy was also a major contributing factor to that.

#### **Tips**

If you are planning to take the HTB CDSA, here are a few tips from my firsthand experience:

1.  **Trust the Academy Process:** Everything you need for the exam is genuinely in the modules. Study them in detail.
2.  **Notes, Notes, and More Notes:** I cannot stress this enough. Organize them by tools and techniques.
3.  **Practice Report Writing:** Before the exam, read several publicly available DFIR reports (e.g., from The DFIR Report). Practice writing based on a scenario. Use a tool like SysReptor, which HTB recommends.
4.  **Manage Your Time:** You have 7 days. Make a plan. You don't need to be at it 24/7. Rest is important to stay fresh and focused.
5.  **Take Lots of Screenshots:** Document every step, every command, and every significant result with a screenshot. You will thank yourself later when you're writing the report.
6.  **Don't Panic:** If you get stuck, take a break. Go for a walk. The solution is often obvious, but you can't see it when you're fatigued.

I hope this detailed breakdown was useful. The HTB CDSA is more than just a certification—it's a fantastic learning experience that truly prepares you for real-world cybersecurity challenges.

If you have any questions, feel free to contact me!
