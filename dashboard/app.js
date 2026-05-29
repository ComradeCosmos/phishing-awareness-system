/* ==========================================================================
   Phishing Shield Dashboard JavaScript Logic
   Includes: Sandbox Inbox Simulator, SMTP Header Analyzer, Typosquatting Checker,
             and Interactive Security Awareness Quiz.
   ========================================================================== */

document.addEventListener("DOMContentLoaded", () => {
    
    /* ==========================================================================
       1. Core Data Structures
       ========================================================================== */

    // 5 Phishing Emails Data
    const emailsData = [
        {
            id: 0,
            avatar: "P",
            senderName: "PayPal Security Alert",
            senderEmail: "security-update-alert@paypa1-support.com",
            time: "12:12 PM",
            risk: "high",
            subject: "URGENT: Your account has been temporarily suspended!",
            snippet: "Suspicious activity was detected on your account. To protect your funds...",
            htmlBody: `
                <div style="font-family: Arial, sans-serif; color: #333333; line-height: 1.6; padding: 20px; border: 1px solid #eeeeee; max-width: 600px; margin: 0 auto;">
                    <div style="background-color: #003087; padding: 15px; text-align: center; color: white; font-weight: bold; font-size: 24px; font-style: italic;">
                        PayPaI
                    </div>
                    <div style="padding: 20px;">
                        <div style="background-color: #fff3cd; border-left: 5px solid #ffc107; padding: 12px; margin-bottom: 20px;">
                            <strong>Warning:</strong> Suspicious activity was detected on your account. To protect your funds, we have temporarily restricted account access.
                        </div>
                        <p>Dear Customer,</p>
                        <p>We recently noticed some transactions that seem unusual compared to your normal activity. As a security measure, we have suspended your account access until we can verify your identity.</p>
                        <p><strong>What do I need to do?</strong></p>
                        <p>You must verify your billing details and update your security questions within <strong>24 hours</strong>. Failure to complete verification will result in permanent suspension.</p>
                        <div style="text-align: center; margin: 25px 0;">
                            <a href="#" style="display: inline-block; padding: 12px 24px; background-color: #0070ba; color: #ffffff !important; text-decoration: none; border-radius: 20px; font-weight: bold;">Verify My Account Now</a>
                        </div>
                        <p>Sincerely,<br>PayPal Security Operations Team</p>
                    </div>
                </div>
            `,
            auth: { spf: "PASS", dkim: "PASS", dmarc: "PASS", dmarcVal: "PASS (p=QUARANTINE)" },
            flags: [
                { top: 5, left: 52, title: "Typosquatted Brand Logo", threat: "Spoofing", risk: "CRITICAL", desc: "The header logo reads 'PayPaI' using a capital letter 'I' at the end to trick the human eye into reading 'PayPal'. This is a visual homoglyph trap.", mitigation: "Inspect logo font consistency and check associated links." },
                { top: 22, left: 16, title: "Generic Customer Salutation", threat: "Social Engineering", risk: "HIGH", desc: "Using 'Dear Customer' instead of the customer's actual registered name is a prime indicator of automated mass-phishing distribution. PayPal always addresses users by their full name.", mitigation: "Be highly suspicious of generic greetings from institutions claiming holding your financial assets." },
                { top: 27, left: 74, title: "Urgency Pressure Threat", threat: "Fear Trigger", risk: "HIGH", desc: "The email demands compliance within '24 hours' and threatens permanent loss of funds. Attackers use extreme time bounds to cause panic, bypassing logical checks.", mitigation: "Never let urgency prompts accelerate your actions. Take a breath and verify independently." },
                { top: 33, left: 50, title: "Spoofed Hyperlink Destination", threat: "Credential Harvesting", risk: "CRITICAL", desc: "The 'Verify My Account Now' button does not point to paypal.com. It directs to paypa1-support.com, a newly registered malicious landing site designed to clone your login password.", mitigation: "Always hover over hyperlinks to inspect the actual web destination before clicking." }
            ]
        },
        {
            id: 1,
            avatar: "L",
            senderName: "The UK National Lottery",
            senderEmail: "claims-dept@uk-national-jackpot-winner.net",
            time: "1:34 PM",
            risk: "high",
            subject: "CONGRATULATIONS!!! You Have Won £2,500,000 GBP! (Ref: UK/9482/2026)",
            snippet: "This is to inform you that you have been selected as a Category 'A' winner...",
            htmlBody: `
                <div style="font-family: Arial, sans-serif; color: #333333; line-height: 1.5; padding: 20px; border: 2px dashed #00b981; max-width: 600px; margin: 0 auto; background-color: #f6fcf9;">
                    <h2 style="color: #00b981; text-align: center; border-bottom: 2px solid #00b981; padding-bottom: 10px;">THE UK NATIONAL LOTTERY</h2>
                    <p style="font-size: 11px; text-align: right; color: #777;">Ref: UK/9482/2026</p>
                    <p><strong>OFFICIAL WINNINGS NOTIFICATION</strong></p>
                    <p>We are delighted to inform you that your email address has emerged as a Category 'A' winner in our international promotion. You have been awarded a lump sum payout of <strong>£2,500,000 GBP</strong>.</p>
                    <p>Your address was selected at random from a global corporate directory of over 10,000,000 corporate records.</p>
                    <p>To process your claim, please reply to this email immediately with your full name, physical address, date of birth, and a high-resolution scan of your passport or driver's license.</p>
                    <div style="background-color: #e0f2fe; padding: 12px; border-radius: 6px; margin: 15px 0; border: 1px solid #bae6fd;">
                        <strong>Attachment:</strong> Lottery_Winning_Certificate_2026.zip (18.4 KB)
                    </div>
                    <p style="color: #d97706; font-size: 12px;"><strong>WARNING:</strong> Keep your winning details completely confidential to prevent double claims and secure payout.</p>
                    <p>Regards,<br>Lady Beatrice Windsor</p>
                </div>
            `,
            auth: { spf: "PASS", dkim: "PASS", dmarc: "FAIL", dmarcVal: "FAIL (p=NONE - Policy Disabled)" },
            flags: [
                { top: 5, left: 78, title: "Mismatched High-Risk Domain", threat: "Domain Spoofing", risk: "HIGH", desc: "The sender domain 'uk-national-jackpot-winner.net' claims representation of the official UK National Lottery. The official lottery domain is national-lottery.co.uk. The registered domain is suspicious.", mitigation: "Check WHOIS registry information to view creation dates of weird domains." },
                { top: 22, left: 63, title: "Extreme Windfall Scam", threat: "Greed Trap", risk: "HIGH", desc: "Claiming a massive financial prize (£2.5M) for a drawing the victim never purchased a ticket for. This operates on greed psychological triggers.", mitigation: "Remember: If it is too good to be true, it is always a scam. You cannot win a lottery you did not buy a ticket for." },
                { top: 25, left: 55, title: "Identity Harvesting Request", threat: "PII Theft", risk: "HIGH", desc: "Requesting highly confidential documents (scans of passport or driver's license). Once captured, attackers use these to commit financial fraud and open corporate bank lines under your name.", mitigation: "Never send identity papers or copies of drivers licenses over unverified email." },
                { top: 29, left: 40, title: "Hazardous Archive Attachment", threat: "Malware Payload", risk: "CRITICAL", desc: "The ZIP archive 'Lottery_Winning_Certificate_2026.zip' carries a hidden malicious script file. When unzipped, it triggers an outbound connection, deploying Trojan malware.", mitigation: "Never open unexpected files with extension archives (.zip, .iso) from outside senders." },
                { top: 32, left: 55, title: "Artificial Isolation / Secrecy", threat: "Social Isolation", risk: "HIGH", desc: "Instructing the victim to keep the notice secret blocks them from consulting IT support, security analysts, or colleagues who would spot the fraud.", mitigation: "Any instruction to keep communications confidential or hidden from IT is a major red flag." }
            ]
        },
        {
            id: 2,
            avatar: "R",
            senderName: "Robert Vance (CEO)",
            senderEmail: "ceo.targetcorp@gmail.com",
            time: "2:15 PM",
            risk: "critical",
            subject: "CONFIDENTIAL: Urgent Wire Transfer Request - Project Aurora",
            snippet: "Hi Sarah, Are you at your desk? I am currently in a highly confidential board meeting...",
            htmlBody: `
                <div style="font-family: monospace; font-size: 14px; color: #000000; padding: 20px; max-width: 600px; margin: 0 auto; line-height: 1.5; background-color: #ffffff;">
                    <p>Hi Sarah,</p>
                    <p>Are you at your desk? I am currently in a highly confidential board meeting regarding our upcoming corporate acquisition (Project Aurora). I cannot take any phone calls right now, so please respond via this email address.</p>
                    <p>We need to close a standard deposit payment of $45,000 USD to our legal team immediately to prevent delays in the transaction. I need you to initiate a wire transfer manually today.</p>
                    <p>Please send me the wire transfer form and current routing details. I will provide the recipient's bank routing and account information as soon as you confirm you are ready to process it.</p>
                    <p>This acquisition is highly sensitive, so please keep this matter completely confidential. Do not discuss it with anyone else in the office.</p>
                    <p>I'm counting on you to get this done quickly before the bank closes. Let me know when you have initiated the transfer.</p>
                    <p>Regards,<br><br>Robert Vance<br>Chief Executive Officer<br>Target Corp.<br><i>Sent from my iPad</i></p>
                </div>
            `,
            auth: { spf: "PASS", dkim: "PASS", dmarc: "PASS", dmarcVal: "PASS (p=NONE for gmail.com)" },
            flags: [
                { top: 5, left: 45, title: "CEO Name Spoofing", threat: "Impersonation", risk: "CRITICAL", desc: "The display name claims 'Robert Vance', the authentic CEO. However, the email address behind the display name is 'ceo.targetcorp@gmail.com' (a free public Gmail account). The CEO would never use Gmail for corporate finances.", mitigation: "Always check the actual email address, not just the display name." },
                { top: 12, left: 35, title: "Blocked Call Channel Verification", threat: "Out-of-Band Prevention", risk: "CRITICAL", desc: "The attacker states 'I cannot take any phone calls right now'. This is designed to prevent the CFO from calling the real CEO to verify the wire transfer.", mitigation: "Never bypass verbal verification. If an executive claims they cannot talk, reach out through pre-established corporate communication channels like Teams." },
                { top: 15, left: 38, title: "Urgent Wire Transfer Request", threat: "BEC / Financial Theft", risk: "CRITICAL", desc: "Requesting a $45,000 wire transfer for a confidential corporate merger. BEC (Business Email Compromise) is the leading cause of corporate wire fraud, with millions lost daily.", mitigation: "All wire transfers must pass multiple layers of institutional approvals and verification, regardless of executive urgency." },
                { top: 22, left: 52, title: "Forced Secrecy Policy Bypass", threat: "Social Engineering", risk: "CRITICAL", desc: "The email demands complete silence ('keep this completely confidential'). This is engineered to prevent the employee from looping in IT or the general accounting team.", mitigation: "Corporate transactions are subject to checks and balances. Never commit to silent or un-audited transfers." }
            ]
        },
        {
            id: 3,
            avatar: "M",
            senderName: "Target Corp IT Helpdesk",
            senderEmail: "helpdesk@targetcorp-it-support.net",
            time: "3:22 PM",
            risk: "high",
            subject: "Action Required: Your Single Sign-On (SSO) Password Expires in 24 Hours!",
            snippet: "Your corporate Active Directory / Single Sign-On (SSO) network password is scheduled...",
            htmlBody: `
                <div style="font-family: 'Segoe UI', Tahoma, sans-serif; color: #333333; line-height: 1.5; padding: 20px; border: 1px solid #e0e0e0; max-width: 550px; margin: 0 auto; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
                    <div style="background-color: #0078d4; color: #ffffff; padding: 20px; font-weight: 600; font-size: 18px;">
                        Microsoft Office 365 - Single Sign-On Security Update
                    </div>
                    <div style="padding: 20px;">
                        <p>Dear Corporate User,</p>
                        <p>Your corporate Active Directory / Single Sign-On (SSO) network password is scheduled to expire in <span style="color: #d83b01; font-weight: bold;">24 hours</span> as part of our quarterly network security update.</p>
                        <p>To avoid any disruption to your work email, Teams, OneDrive, and corporate network share portals, you must log in immediately and confirm your current password credentials to authorize the extension.</p>
                        <p>If you do not complete this verification before the deadline, your account will be locked out and you will be unable to access corporate systems.</p>
                        <div style="margin: 25px 0;">
                            <a href="#" style="display: inline-block; padding: 12px 24px; background-color: #0078d4; color: #ffffff !important; text-decoration: none; font-weight: 600;">Keep My Current Password</a>
                        </div>
                        <p>Best regards,</p>
                        <p><strong>Target Corp IT Infrastructure Support</strong><br>Helpdesk Ticket ID: #AD-830219-EXP</p>
                    </div>
                </div>
            `,
            auth: { spf: "PASS", dkim: "PASS", dmarc: "PASS", dmarcVal: "PASS (p=REJECT)" },
            flags: [
                { top: 5, left: 63, title: "Lookalike Corporate IT Domain", threat: "Typosquatting", risk: "CRITICAL", desc: "The sender domain 'targetcorp-it-support.net' mimics an internal corporate support portal. Legitimate corporate emails come from '@target-corp.com'. Attackers register brand-mimic domains.", mitigation: "Check if the IT domain perfectly matches the primary corporate domain." },
                { top: 22, left: 45, title: "Baiting Service Interruption", threat: "Fear / Friction Trap", risk: "HIGH", desc: "The threat of account lockdown and lose of Teams/Outlook access creates friction. Employees will act rashly to prevent disruptions to their daily workflows.", mitigation: "IT departments never prompt users to extend passwords via email clicks. Standard domain systems update in OS prompt windows." },
                { top: 31, left: 35, title: "SSO Credential Harvesting Link", threat: "Credential Harvesting", risk: "CRITICAL", desc: "The 'Keep My Current Password' button targets Active Directory SSO passwords. Clicking loads a clone of the Microsoft corporate portal. Typing credentials exfiltrates them to the attacker.", mitigation: "FIDO2 security keys protect against such harvesting links since they refuse auth on non-authentic domains." }
            ]
        },
        {
            id: 4,
            avatar: "D",
            senderName: "DHL Express Delivery",
            senderEmail: "delivery-notification@dhl-tracking-alert.com",
            time: "4:41 PM",
            risk: "medium",
            subject: "Delivery Failed: Important parcel delivery outstanding - Action required!",
            snippet: "Our courier attempted delivery of your registered international shipment on February 10...",
            htmlBody: `
                <div style="font-family: Arial, sans-serif; color: #333333; line-height: 1.4; padding: 20px; border: 1px solid #ffcc00; max-width: 600px; margin: 0 auto;">
                    <div style="background-color: #d40511; padding: 12px; border-bottom: 5px solid #ffcc00; color: #ffcc00; font-family: Impact, sans-serif; font-size: 28px;">
                        DHL EXPRESS
                    </div>
                    <div style="padding: 20px;">
                        <h3 style="color: #d40511; margin-top: 0;">Your Package Could Not Be Delivered!</h3>
                        <p>Dear Customer,</p>
                        <p>Our courier attempted delivery of your registered international shipment on <strong>February 10, 2026</strong>. However, the delivery attempt failed due to an incomplete street address in our records.</p>
                        <table style="width: 100%; border-collapse: collapse; margin: 15px 0; border: 1px solid #ddd;">
                            <tr style="background-color: #f5f5f5;"><th style="border: 1px solid #ddd; padding: 8px; text-align: left;">Waybill No.</th><td style="border: 1px solid #ddd; padding: 8px;">#DHL-93849-DE</td></tr>
                            <tr><th style="border: 1px solid #ddd; padding: 8px; text-align: left;">Outstanding Fee</th><td style="border: 1px solid #ddd; padding: 8px;">$1.50 USD (Redelivery Admin Fee)</td></tr>
                        </table>
                        <p><strong>Action Required:</strong></p>
                        <p>To schedule a redelivery dispatch, you must pay the outstanding $1.50 fee online. If not settled within <strong>48 hours</strong>, the package will be returned.</p>
                        <div style="margin: 20px 0;">
                            <a href="#" style="display: inline-block; padding: 12px 24px; background-color: #d40511; color: #ffffff !important; text-decoration: none; border-radius: 4px; font-weight: bold;">Reschedule Delivery</a>
                        </div>
                    </div>
                </div>
            `,
            auth: { spf: "PASS", dkim: "PASS", dmarc: "PASS", dmarcVal: "PASS (p=QUARANTINE)" },
            flags: [
                { top: 5, left: 45, title: "Typosquatted Sender Domain", threat: "Brand Spoofing", risk: "HIGH", desc: "Sender 'dhl-tracking-alert.com' is a lookalike domain registering brand names. Real DHL alerts come from @dhl.com or verified subdomains like tracking.dhl.com.", mitigation: "Check official package alerts inside official browser bookmarks or apps." },
                { top: 21, left: 35, title: "Low-Fee Financial Harvesting Trap", threat: "Card Cloning", risk: "HIGH", desc: "Asking for a small fee ($1.50) creates low entry resistance. Victims enter debit/credit cards readily. This immediately steals CVV details for card cloning.", mitigation: "Delivery entities do not hold packages hostage for small online micro-fees. Never enter financial details from email links." },
                { top: 29, left: 24, title: "Interactive Redirection Button", threat: "Form Exploits / Driveby", risk: "CRITICAL", desc: "The 'Reschedule Delivery' button redirect can perform automated cross-site requests or run JavaScript code capturing physical coordinates and system specifications.", mitigation: "Manually query official delivery tracking numbers inside official carrier portals." }
            ]
        },
        {
            id: 5,
            avatar: "S",
            senderName: "Microsoft SharePoint Online",
            senderEmail: "no-reply@sharepoint-docs-portal.com",
            time: "5:12 PM",
            risk: "high",
            subject: "Urgent: Corporate Payroll adjustments shared with you",
            snippet: "User shared the document 'Q1 Payroll Adjustments' with you on Microsoft SharePoint...",
            htmlBody: `
                <div style="font-family: 'Segoe UI', Tahoma, sans-serif; color: #333333; line-height: 1.5; padding: 20px; border: 1px solid #e0e0e0; max-width: 550px; margin: 0 auto;">
                    <div style="background-color: #fafbfc; border-bottom: 1px solid #eeeeee; padding: 15px; display: flex; align-items: center; gap: 10px;">
                        <span style="background-color: #0078d4; color: white; padding: 4px 8px; font-weight: bold; font-size: 11px;">S</span>
                        <span style="font-size: 12px; color: #666666; font-weight: 600;">SharePoint Online</span>
                    </div>
                    <div style="padding: 20px;">
                        <p>Dear Colleague,</p>
                        <p>An external billing consultant has shared a secure document <strong>"Q1 Payroll Adjustments - Private.xlsx"</strong> with you via corporate SharePoint.</p>
                        <p>This file contains confidential corporate payroll audits that require your immediate approval today before final ledger processing.</p>
                        <div style="margin: 25px 0; background-color: #f3f2f1; padding: 15px; border-left: 4px solid #0078d4;">
                            <p style="margin: 0; font-size: 12px; color: #605e5c;">Comment from Sender:</p>
                            <p style="margin: 5px 0 0 0; font-style: italic; font-weight: 600;">"Sarah, please verify line 14 adjustments for the regional sales leads immediately."</p>
                        </div>
                        <div style="text-align: center; margin: 25px 0;">
                            <a href="#" style="display: inline-block; padding: 12px 24px; background-color: #0078d4; color: #ffffff !important; text-decoration: none; font-weight: bold; border-radius: 2px;">Access Secure Spreadsheet</a>
                        </div>
                    </div>
                </div>
            `,
            auth: { spf: "PASS", dkim: "PASS", dmarc: "PASS", dmarcVal: "PASS (p=QUARANTINE)" },
            flags: [
                { top: 5, left: 74, title: "Shared Portal Lookalike Domain", threat: "Typosquatting", risk: "HIGH", desc: "The sender domain 'sharepoint-docs-portal.com' is a lookalike domain registering the brand keyword 'sharepoint'. Real Microsoft document alerts originate from verified '@sharepointonline.com' or '@microsoft.com' systems.", mitigation: "Check document links inside standard corporate chat programs first before logging in." },
                { top: 22, left: 35, title: "Urgent Financial Bait", threat: "Social Engineering", risk: "HIGH", desc: "Using the theme 'Payroll Adjustments' baits employees to click out of curiosity or fear of payroll processing issues.", mitigation: "Always check with the HR or payroll manager verbally before accessing external payroll sheets." },
                { top: 32, left: 50, title: "Microsoft Portal Credential Harvesting", threat: "Form Impersonation", risk: "CRITICAL", desc: "The 'Access Secure Spreadsheet' button directs to a cloned Microsoft Entra ID portal. Typing credentials instantly exfiltrates organizational credentials.", mitigation: "Verify the browser URL bar says login.microsoftonline.com before typing credentials." }
            ]
        },
        {
            id: 6,
            avatar: "H",
            senderName: "Target Corp HR Department",
            senderEmail: "benefits@targetcorp-hr-portal.com",
            time: "6:05 PM",
            risk: "high",
            subject: "Urgent Notice: Open Enrollment Deadline expires today!",
            snippet: "This is a final notice regarding your annual healthcare and corporate benefits open enrollment...",
            htmlBody: `
                <div style="font-family: Arial, sans-serif; color: #333333; line-height: 1.6; padding: 20px; border: 1px solid #e2e8f0; max-width: 600px; margin: 0 auto;">
                    <div style="background-color: #f1f5f9; padding: 15px; border-bottom: 2px solid #334155; font-weight: bold; font-size: 16px;">
                        Target Corp - Human Resources department
                    </div>
                    <div style="padding: 20px;">
                        <p>Dear Employee,</p>
                        <p>Our records indicate that you have <strong>not</strong> completed your annual healthcare benefits open enrollment verification questionnaire for the 2026 calendar year.</p>
                        <p>The final lock-out deadline expires today at 5:00 PM EST. Failure to update your details will result in automatic termination of your current dental, vision, and health coverage, and you will be forced to wait until the next open enrollment cycle in 2027.</p>
                        <div style="text-align: center; margin: 25px 0;">
                            <a href="#" style="display: inline-block; padding: 12px 24px; background-color: #1e293b; color: #ffffff !important; text-decoration: none; border-radius: 4px; font-weight: bold;">Verify Open Enrollment Details</a>
                        </div>
                        <p>Best regards,<br>Target Corp HR Administration Team</p>
                    </div>
                </div>
            `,
            auth: { spf: "PASS", dkim: "PASS", dmarc: "PASS", dmarcVal: "PASS (p=QUARANTINE)" },
            flags: [
                { top: 5, left: 62, title: "Mimicked HR Portal Domain", threat: "Typosquatting", risk: "HIGH", desc: "The domain 'targetcorp-hr-portal.com' spoofing the internal HR portal is registered by external entities. Real internal resources live strictly under target-corp.com or dedicated intranet URLs.", mitigation: "Intranet benefits are normally updated inside corporate HR profiles accessed manually." },
                { top: 22, left: 34, title: "Loss of Healthcare Panic Trigger", threat: "Fear Injection", risk: "HIGH", desc: "Threatening the immediate loss of healthcare benefits for the year builds immense panic, driving employees to comply to bypass disruption.", mitigation: "When panic triggers are hit, contact HR using standard telephone directories to check status." },
                { top: 27, left: 50, title: "Personal Data Harvesting Landing", threat: "PII Harvesting", risk: "CRITICAL", desc: "The verification link redirects to a form asking for SSN, home address, and corporate password credentials.", mitigation: "HR teams never verify enrollment documents via raw hyperlink prompts inside outside emails." }
            ]
        },
        {
            id: 7,
            avatar: "A",
            senderName: "Accounts Receivable - Global Parts",
            senderEmail: "billing@globalparts-logistics.net",
            time: "7:10 PM",
            risk: "high",
            subject: "Overdue Invoice #AP-938291: Immediate payment required",
            snippet: "Please find attached invoice #AP-938291 which is currently 14 days overdue. Immediate payment...",
            htmlBody: `
                <div style="font-family: Arial, sans-serif; color: #333333; line-height: 1.5; padding: 20px; border: 1px solid #cbd5e1; max-width: 580px; margin: 0 auto;">
                    <h3 style="color: #ef4444; border-bottom: 1.5px solid #ef4444; padding-bottom: 8px; margin-top: 0;">OVERDUE INVOICE ALERT</h3>
                    <p>Dear Accounts Payable,</p>
                    <p>Please find attached our invoice <strong>#AP-938291</strong> which is currently 14 days overdue. The outstanding ledger balance of <strong>$8,420.00 USD</strong> requires immediate settlement today.</p>
                    <p>Failure to process payment by the end of business today will result in a 5% compounding late fee and immediate disruption to outstanding parts shipments.</p>
                    <div style="margin: 20px 0; background-color: #f8fafc; border: 1px solid #e2e8f0; padding: 12px; border-radius: 4px;">
                        <strong>Attachment:</strong> Invoice_AP-938291.zip (24.1 KB)
                    </div>
                    <p>Please review the attachment for wire transfer instructions and update the transaction status today.</p>
                    <p>Regards,<br>Finance Operations - Global Parts Logistics</p>
                </div>
            `,
            auth: { spf: "PASS", dkim: "PASS", dmarc: "FAIL", dmarcVal: "FAIL (p=NONE)" },
            flags: [
                { top: 5, left: 52, title: "Accounts Payable Urgency bait", threat: "Friction Trigger", risk: "HIGH", desc: "Threatening supply chain delays and compounding late fees pushes the AP officer to process the transaction to prevent organizational disruption.", mitigation: "All vendor requests must pass through three-way matching against PO records." },
                { top: 21, left: 34, title: "Invoice Malware Downloader Package", threat: "Malware Delivery", risk: "CRITICAL", desc: "The ZIP archive 'Invoice_AP-938291.zip' contains a hidden .lnk script. Unzipping and running it downloads an execution payload carrying secondary stage Trojan spyware.", mitigation: "Never launch zip folders claiming invoices from unknown vendor logistics servers." }
            ]
        },
        {
            id: 8,
            avatar: "I",
            senderName: "Target Corp Cyber Security Response",
            senderEmail: "incident-response@targetcorp-alert.com",
            time: "8:30 PM",
            risk: "critical",
            subject: "Crucial Security Action: Corporate Data Breach - Password reset required",
            snippet: "We have detected an active credential compromise matching your target account...",
            htmlBody: `
                <div style="font-family: monospace; font-size: 13px; color: #1e293b; padding: 20px; border: 1.5px solid #0f172a; max-width: 550px; margin: 0 auto; background-color: #fafbfc;">
                    <div style="background-color: #0f172a; color: white; padding: 12px; font-weight: bold; text-align: center;">
                        TARGET CORP - EMERGENCY SECURITY ALERTER
                    </div>
                    <p style="margin-top: 15px;"><strong>ALERT ID: #INC-2026-9382</strong></p>
                    <p>Dear Employee,</p>
                    <p>Our intrusion detection monitoring system has logged an active credential compromise matching your account parameters originating from an unauthorized IP in a blacklisted region.</p>
                    <p>As a mandatory safety precaution, you must reset your SSO corporate domain password within <strong>1 hour</strong>. Failure to authenticate and update your keys immediately will result in immediate suspension of all network access and corporate credentials.</p>
                    <div style="text-align: center; margin: 25px 0;">
                        <a href="#" style="display: inline-block; padding: 12px 24px; background-color: #0f172a; color: #ffffff !important; text-decoration: none; font-weight: bold; border-radius: 4px;">Initialize Secure Reset Workspace</a>
                    </div>
                    <p>Best regards,<br>Corporate Incident Triage Team</p>
                </div>
            `,
            auth: { spf: "PASS", dkim: "PASS", dmarc: "PASS", dmarcVal: "PASS (p=QUARANTINE)" },
            flags: [
                { top: 5, left: 63, title: "Emergency Mimic Domain", threat: "Typosquatting", risk: "CRITICAL", desc: "The domain 'targetcorp-alert.com' is an external spoof server registered to impersonate the SOC. Standard incident responses are sent from authentic @target-corp.com vectors.", mitigation: "Cybersecurity teams do not issue automated raw hyperlink prompts asking for SSO resets under brief deadlines." },
                { top: 22, left: 35, title: "Breach Fear Trigger", threat: "Fear Engineering", risk: "CRITICAL", desc: "Claiming an active breach creates high psychological panic, encouraging the employee to click immediately to protect their workspace.", mitigation: "Check official internal security portals or channels to confirm simulation statuses." },
                { top: 31, left: 50, title: "Corporate SSO Impersonation Landing", threat: "Credential Harvesting", risk: "CRITICAL", desc: "The reset button links to an exact copy of the corporate SSO verification desk, built to capture domain username and password sets.", mitigation: "Always check URL details in the browser frame before submitting any Active Directory password reset." }
            ]
        },
        {
            id: 9,
            avatar: "C",
            senderName: "Chase Bank Commercial Alert",
            senderEmail: "security@chase-verification-service.com",
            time: "9:24 PM",
            risk: "high",
            subject: "Security Restriction: Suspicious login blocked - Identity verification",
            snippet: "We blocked a suspicious login attempt to your Chase commercial account. Immediate verification required...",
            htmlBody: `
                <div style="font-family: Arial, sans-serif; color: #333333; line-height: 1.6; padding: 20px; border: 1px solid #1172b6; max-width: 580px; margin: 0 auto;">
                    <div style="background-color: #1172b6; padding: 15px; text-align: center; color: white; font-weight: bold; font-size: 20px;">
                        CHASE
                    </div>
                    <div style="padding: 20px;">
                        <p>Dear Commercial Account Holder,</p>
                        <p>We recently blocked a suspicious login attempt originating from a device in Russia trying to access your commercial banking profile today at 11:24 AM.</p>
                        <p>To protect your corporate funds and reset security permissions, you must immediately confirm your billing profiles, business routing keys, and account parameters.</p>
                        <p>If not completed within <strong>24 hours</strong>, we will place a temporary hold on all outgoing wire transactions and payroll accounts.</p>
                        <div style="text-align: center; margin: 25px 0;">
                            <a href="#" style="display: inline-block; padding: 12px 24px; background-color: #1172b6; color: #ffffff !important; text-decoration: none; font-weight: bold;">Unlock Business Account</a>
                        </div>
                        <p>Regards,<br>Chase Commercial Risk Management Office</p>
                    </div>
                </div>
            `,
            auth: { spf: "PASS", dkim: "PASS", dmarc: "PASS", dmarcVal: "PASS (p=QUARANTINE)" },
            flags: [
                { top: 5, left: 52, title: "Financing Verification Mimic Domain", threat: "Typosquatting", risk: "HIGH", desc: "The domain 'chase-verification-service.com' mimics official Chase Bank channels. Chase commercial notifications arrive only under authentic @chase.com or verified subdomains.", mitigation: "Never trust email warnings regarding banking holds. Check commercial accounts inside official bookmarks." },
                { top: 22, left: 34, title: "Payroll Lock Threat", threat: "Financial Urgency", risk: "HIGH", desc: "Threatening to lock payroll outgoing wire lines creates absolute panic for the accountant, forcing immediate compliance.", mitigation: "Corporate banking relationships have direct support representatives. Verify alerts through them via verified phone numbers." },
                { top: 31, left: 50, title: "Bank Account Credential Harvesting Portal", threat: "Credential Harvesting", risk: "CRITICAL", desc: "The link directs to a cloned business banking portal aimed at capturing commercial login IDs, PINs, and security answers.", mitigation: "Verify absolute domain addresses in browser frames before entering commercial bank keys." }
            ]
        },
        {
            id: 10,
            avatar: "S",
            senderName: "DocuSign Signature Service",
            senderEmail: "signature-desk@docusign-verification.net",
            time: "10:05 PM",
            risk: "high",
            subject: "Urgent: Signature Required - Mutual NDA and Retention Agreement",
            snippet: "You have been requested to review and sign the document 'NDA_and_Retention_Agreement.pdf' inside DocuSign...",
            htmlBody: `
                <div style="font-family: Arial, sans-serif; color: #333333; line-height: 1.5; padding: 20px; border: 1px solid #e5e7eb; max-width: 600px; margin: 0 auto; background-color: #ffffff;">
                    <div style="background-color: #1e293b; padding: 15px; text-align: center; color: #fbbf24; font-weight: bold; font-size: 20px;">
                        DocuSign
                    </div>
                    <div style="padding: 25px;">
                        <p>Dear Candidate,</p>
                        <p>You have been requested by corporate counsel to review and sign the legal document <strong>"Mutual NDA and Retention Agreement.pdf"</strong> via our secure signature workspace.</p>
                        <p>This document contains sensitive details regarding pending workforce structures and retention incentives. To complete the process and keep your onboarding sequence active, you must click the link below and sign the document today.</p>
                        <div style="text-align: center; margin: 25px 0;">
                            <a href="#" style="display: inline-block; padding: 12px 24px; background-color: #fbbf24; color: #1e293b !important; text-decoration: none; font-weight: bold; border-radius: 4px;">Review & Sign Document</a>
                        </div>
                        <p>Please note that this document signature request will expire within <strong>12 hours</strong>.</p>
                        <p>Best regards,<br>DocuSign Administrative Service</p>
                    </div>
                </div>
            `,
            auth: { spf: "PASS", dkim: "PASS", dmarc: "PASS", dmarcVal: "PASS (p=QUARANTINE)" },
            flags: [
                { top: 5, left: 52, title: "DocuSign Lookalike Domain", threat: "Brand Typosquatting", risk: "CRITICAL", desc: "The domain 'docusign-verification.net' mimics authentic DocuSign infrastructure. Real DocuSign notifications resolve under 'docusign.com' or 'docusign.net'.", mitigation: "Never log in or sign documents accessed via external domain extensions." },
                { top: 22, left: 34, title: "NDA Urgency Pressure", threat: "Social Engineering", risk: "HIGH", desc: "Using the theme of an urgent NDA and workforce retention incentive exploits employee curiosity and fear under a strict 12-hour limit.", mitigation: "Check with internal legal departments verbally to verify signature requests." },
                { top: 31, left: 50, title: "SSO Credential Harvesting Portal", threat: "Form Exploitation", risk: "CRITICAL", desc: "The sign link loads a spoofed portal capturing email and corporate password credentials.", mitigation: "Check browser address frames for the official secure signature login domains." }
            ]
        },
        {
            id: 11,
            avatar: "Z",
            senderName: "Zoom Meeting Alerter",
            senderEmail: "no-reply@zoom-briefing-alert.us",
            time: "10:42 PM",
            risk: "high",
            subject: "Action Required: Mandatory Q2 Corporate Reorganization Briefing - Zoom Link",
            snippet: "A mandatory all-hands corporate restructuring briefing has been scheduled for tomorrow at 9:00 AM. Please download...",
            htmlBody: `
                <div style="font-family: Arial, sans-serif; color: #333333; line-height: 1.5; padding: 20px; border: 1px solid #cbd5e1; max-width: 600px; margin: 0 auto; background-color: #f8fafc;">
                    <div style="background-color: #2d8cff; padding: 15px; text-align: center; color: white; font-weight: bold; font-size: 24px;">
                        zoom
                    </div>
                    <div style="padding: 25px; background-color: #ffffff;">
                        <h3 style="color: #2d8cff; margin-top: 0;">Restructuring Briefing - All Hands</h3>
                        <p>Dear Employee,</p>
                        <p>A mandatory Zoom video conference has been scheduled for tomorrow morning regarding the upcoming Q2 corporate restructuring program and team reassignments.</p>
                        <p>To access the call securely and review details of the transition catalog, you must download the customized secure connection utility attached below.</p>
                        <div style="background-color: #f1f5f9; padding: 12px; border-radius: 4px; margin: 15px 0; border: 1px solid #cbd5e1; font-family: monospace; font-size: 13px;">
                            <strong>Attachment:</strong> Zoom_Briefing_Workspace_Update.zip (142.1 KB)
                        </div>
                        <p>Ensure the connector utility is unzipped and run prior to the 9:00 AM call time to avoid account lockout during the meeting.</p>
                        <p>Regards,<br>Zoom Communications Administration Office</p>
                    </div>
                </div>
            `,
            auth: { spf: "PASS", dkim: "PASS", dmarc: "FAIL", dmarcVal: "FAIL (p=NONE)" },
            flags: [
                { top: 5, left: 52, title: "Lookalike Zoom Domain", threat: "Typosquatting", risk: "HIGH", desc: "The sender domain 'zoom-briefing-alert.us' mimics official Zoom channels. Authentic Zoom communications resolve strictly under 'zoom.us' or 'zoom.com'.", mitigation: "Never download connection packages or update files from unauthorized external email channels." },
                { top: 22, left: 34, title: "Workforce Transition Bait", threat: "Fear Injection", risk: "CRITICAL", desc: "The threat of corporate restructuring and team reassignments plays on employee career anxieties, bypassing logical defenses.", mitigation: "Official HR restructuring notices arrive via standard internal announcements, never requiring custom ZIP update tools." },
                { top: 29, left: 40, title: "Malicious Archive Attachment", threat: "Trojan Downloader", risk: "CRITICAL", desc: "The attachment 'Zoom_Briefing_Workspace_Update.zip' contains a malicious script payload designed to infect endpoints.", mitigation: "Never extract or execute installer archives received from outside sources." }
            ]
        },
        {
            id: 12,
            avatar: "T",
            senderName: "Microsoft Teams System Alert",
            senderEmail: "teams-chat-alert@microsoft-teams-corporate.com",
            time: "11:15 PM",
            risk: "high",
            subject: "System Notification: Direct mention in Target Corp HR-Private channel",
            snippet: "You have a direct mention from HR Administration in the chat thread regarding the pending Q2 workforce transition...",
            htmlBody: `
                <div style="font-family: 'Segoe UI', Tahoma, sans-serif; color: #333333; line-height: 1.5; padding: 20px; border: 1px solid #e0e0e0; max-width: 580px; margin: 0 auto; background-color: #f3f2f1;">
                    <div style="background-color: #6264a7; color: white; padding: 15px; font-weight: bold; font-size: 16px;">
                        Microsoft Teams
                    </div>
                    <div style="padding: 25px; background-color: #ffffff;">
                        <p style="color: #6264a7; font-weight: bold; margin-top: 0;">HR Admin mentioned you in 'Workforce Audit List'</p>
                        <p>Dear Employee,</p>
                        <p>You have been tagged in a private HR thread regarding the upcoming payroll ledger and transition updates. Please review the chat snippet below:</p>
                        <div style="background-color: #f3f2f1; padding: 12px; margin: 15px 0; border-left: 4px solid #6264a7; font-style: italic;">
                            "Please check the spreadsheet linked below. We need to verify these compensation adjusters before Ledger 3 lock."
                        </div>
                        <div style="text-align: center; margin: 25px 0;">
                            <a href="#" style="display: inline-block; padding: 12px 24px; background-color: #6264a7; color: #ffffff !important; text-decoration: none; font-weight: bold; border-radius: 4px;">Reply in Teams</a>
                        </div>
                    </div>
                </div>
            `,
            auth: { spf: "PASS", dkim: "PASS", dmarc: "PASS", dmarcVal: "PASS (p=REJECT)" },
            flags: [
                { top: 5, left: 52, title: "Spoofed Teams Chat Server", threat: "Typosquatting", risk: "CRITICAL", desc: "The domain 'microsoft-teams-corporate.com' is registered externally to spoof teams notifications. Authentic notifications resolve under Microsoft systems.", mitigation: "Access Microsoft Teams directly through your local OS app interface rather than email prompts." },
                { top: 22, left: 34, title: "HR Private Mention Bait", threat: "Social Engineering", risk: "HIGH", desc: "Mentioning HR private boards and payroll ledger changes baits employee curiosity and career concerns to execute immediate logins.", mitigation: "Verify private mention tags directly inside the native Teams application sidebar." },
                { top: 31, left: 50, title: "SSO Credential Harvesting Kit", threat: "Form Exploits", risk: "CRITICAL", desc: "The 'Reply in Teams' button directs to a replica SSO portal designed to harvest Active Directory logins.", mitigation: "Verify browser URL parameters strictly say login.microsoftonline.com prior to typing corporate credentials." }
            ]
        },
        {
            id: 13,
            avatar: "G",
            senderName: "Google Docs (via Drive)",
            senderEmail: "comments-noreply@googledocs-security-collaboration.com",
            time: "11:50 PM",
            risk: "high",
            subject: "Document Shared: \"Salary_Review_and_Bonus_Q2_TargetCorp\" - Comment tagged you",
            snippet: "User shared a Google Doc with you and tagged you in a comment regarding your Q2 performance bonus adjustments...",
            htmlBody: `
                <div style="font-family: Arial, sans-serif; color: #333333; line-height: 1.5; padding: 20px; border: 1px solid #e1e8ed; max-width: 580px; margin: 0 auto; background-color: #ffffff;">
                    <div style="background-color: #f8fafc; border-bottom: 1px solid #e1e8ed; padding: 15px; font-weight: bold; color: #4b5563;">
                        Google Drive
                    </div>
                    <div style="padding: 25px;">
                        <p>Hello,</p>
                        <p>An external billing collaborator has shared a Google Doc with you and tagged your email in a document comment thread.</p>
                        <div style="margin: 20px 0; background-color: #f1f5f9; padding: 15px; border-radius: 6px; border-left: 4px solid #10b981;">
                            <p style="margin: 0; font-weight: bold; color: #1f2937;">Salary_Review_and_Bonus_Q2_TargetCorp.gdoc</p>
                            <p style="margin: 10px 0 0 0; font-style: italic; color: #4b5563;">"Please verify your performance bonus percentage in line 24 before final release tomorrow morning."</p>
                        </div>
                        <div style="text-align: center; margin: 25px 0;">
                            <a href="#" style="display: inline-block; padding: 12px 24px; background-color: #10b981; color: #ffffff !important; text-decoration: none; font-weight: bold; border-radius: 4px;">Open in Docs</a>
                        </div>
                    </div>
                </div>
            `,
            auth: { spf: "PASS", dkim: "PASS", dmarc: "PASS", dmarcVal: "PASS (p=QUARANTINE)" },
            flags: [
                { top: 5, left: 52, title: "Spoofed Google Drive Address", threat: "Typosquatting", risk: "CRITICAL", desc: "The domain 'googledocs-security-collaboration.com' mimics official Google comment systems. Authentic Google Drive comment alerts arrive from '@google.com'.", mitigation: "Check your shared document queue inside your corporate Google Drive app manually." },
                { top: 22, left: 34, title: "Compensation Bonus Bait", threat: "Greed Trigger", risk: "HIGH", desc: "Reviewing a compensation bonus adjustment triggers positive greed emotion, lowering standard security defenses and pushing the employee to click.", mitigation: "HR departments do not verify salary metrics using comment tags in unauthenticated public document shares." },
                { top: 31, left: 50, title: "Credential Harvesting Dashboard", threat: "Form Capture", risk: "CRITICAL", desc: "The 'Open in Docs' button leads to a lookalike SSO page designed to harvest your organizational login username and password.", mitigation: "Check URL parameters in browser bars prior to entering any corporate password." }
            ]
        }
    ];

    // SMTP Raw Headers Data
    const rawHeadersData = [
        `Return-Path: <security-update-alert@paypa1-support.com>
Received: from mail.paypa1-support.com (mail.paypa1-support.com [198.51.100.42])
        by mx.corporate-mail-gateway.com with ESMTPS id p91si145892plh.112.2026.02.10.04.12.30
        for <employee@target-corp.com>;
        Tue, 10 Feb 2026 04:12:31 -0800 (PST)
<span class="header-clickable" data-field="spf">Received-SPF: pass</span> (mx.corporate-mail-gateway.com: domain of security-update-alert@paypa1-support.com designates 198.51.100.42 as permitted sender) client-ip=198.51.100.42;
<span class="header-clickable" data-field="auth">Authentication-Results: mx.corporate-mail-gateway.com;</span>
       spf=pass (sender IP is 198.51.100.42) smtp.mailfrom=security-update-alert@paypa1-support.com;
       dkim=pass header.i=@paypa1-support.com header.s=default header.b=P7fD2Gz8;
       dmarc=pass (p=QUARANTINE sp=NONE dis=NONE) header.from=paypa1-support.com
<span class="header-clickable" data-field="dkim">DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;</span>
        d=paypa1-support.com; s=default;
        h=from:to:subject:date:message-id:mime-version:content-type;
        bh=9A/B4C5D6E7F8G9H0I1J2K3L4M5N6O7P8Q9R0S1T2U=;
        b=P7fD2Gz8sH9iJ0kK1lM2nO3pQ4rS5tU6vW7xY8z9A0B1C2D3E4F5G6H7I8J9K0L1
<span class="header-clickable" data-field="from">From: "PayPal Security Alert" &lt;security-update-alert@paypa1-support.com&gt;</span>
To: "Valued Customer" &lt;employee@target-corp.com&gt;
Subject: URGENT: Your account has been temporarily suspended!
Date: Tue, 10 Feb 2026 12:12:28 +0000
<span class="header-clickable" data-field="msgid">Message-ID: &lt;0100018a1a36-3a8e2b9c-4d5e-6f7a-8b9c-d0e1f2a3b4c5@paypa1-support.com&gt;</span>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"`,

        `Return-Path: <claims-dept@uk-national-jackpot-winner.net>
Received: from mail.uk-national-jackpot-winner.net (mail.uk-national-jackpot-winner.net [203.0.113.88])
        by mx.corporate-mail-gateway.com with ESMTPS id o18si854932pld.98.2026.02.10.05.34.12
        for &lt;employee@target-corp.com&gt;;
        Tue, 10 Feb 2026 05:34:15 -0800 (PST)
<span class="header-clickable" data-field="spf">Received-SPF: pass</span> (mx.corporate-mail-gateway.com: domain of claims-dept@uk-national-jackpot-winner.net designates 203.0.113.88 as permitted sender) client-ip=203.0.113.88;
<span class="header-clickable" data-field="auth">Authentication-Results: mx.corporate-mail-gateway.com;</span>
       spf=pass (sender IP is 203.0.113.88) smtp.mailfrom=claims-dept@uk-national-jackpot-winner.net;
       dkim=pass header.i=@uk-national-jackpot-winner.net header.s=default;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=uk-national-jackpot-winner.net
<span class="header-clickable" data-field="from">From: "The UK National Lottery" &lt;claims-dept@uk-national-jackpot-winner.net&gt;</span>
<span class="header-clickable" data-field="to">To: &lt;undisclosed-recipients:;&gt;</span>
Subject: CONGRATULATIONS!!! You Have Won £2,500,000 GBP! (Ref: UK/9482/2026)
Date: Tue, 10 Feb 2026 13:34:10 +0000
<span class="header-clickable" data-field="msgid">Message-ID: &lt;LO-9482-2026-8874-Claims@uk-national-jackpot-winner.net&gt;</span>
MIME-Version: 1.0`,

        `Return-Path: <ceo.targetcorp@gmail.com>
Received: from mail-sourcemail.google.com (mail-sourcemail.google.com [209.85.220.41])
        by mx.corporate-mail-gateway.com with ESMTPS id c45si942941plh.12.2026.02.10.06.15.22
        for &lt;cfo@target-corp.com&gt;;
        Tue, 10 Feb 2026 06:15:24 -0800 (PST)
<span class="header-clickable" data-field="spf">Received-SPF: pass</span> (mx.corporate-mail-gateway.com: domain of ceo.targetcorp@gmail.com designates 209.85.220.41 as permitted sender) client-ip=209.85.220.41;
<span class="header-clickable" data-field="auth">Authentication-Results: mx.corporate-mail-gateway.com;</span>
       spf=pass (sender IP is 209.85.220.41) smtp.mailfrom=ceo.targetcorp@gmail.com;
       dkim=pass header.i=@gmail.com header.s=20230601;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gmail.com
<span class="header-clickable" data-field="from">From: "Robert Vance" &lt;ceo.targetcorp@gmail.com&gt;</span>
To: "Sarah Jenkins" &lt;cfo@target-corp.com&gt;
Subject: CONFIDENTIAL: Urgent Wire Transfer Request - Project Aurora
Date: Tue, 10 Feb 2026 14:15:20 +0000
<span class="header-clickable" data-field="msgid">Message-ID: &lt;CAF=2J_vJ=gXz8a7F-y5Z=H6nO+M-O8d9w_Q@mail.gmail.com&gt;</span>
MIME-Version: 1.0`,

        `Return-Path: <helpdesk@targetcorp-it-support.net>
Received: from mail.targetcorp-it-support.net (mail.targetcorp-it-support.net [192.0.2.105])
        by mx.corporate-mail-gateway.com with ESMTPS id x42si284920plg.77.2026.02.10.07.22.18
        for &lt;employee@target-corp.com&gt;;
        Tue, 10 Feb 2026 07:22:20 -0800 (PST)
<span class="header-clickable" data-field="spf">Received-SPF: pass</span> (mx.corporate-mail-gateway.com: domain of helpdesk@targetcorp-it-support.net designates 192.0.2.105 as permitted sender) client-ip=192.0.2.105;
<span class="header-clickable" data-field="auth">Authentication-Results: mx.corporate-mail-gateway.com;</span>
       spf=pass (sender IP is 192.0.2.105) smtp.mailfrom=helpdesk@targetcorp-it-support.net;
       dkim=pass header.i=@targetcorp-it-support.net header.s=itkey;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=targetcorp-it-support.net
<span class="header-clickable" data-field="from">From: "Target Corp IT Helpdesk" &lt;helpdesk@targetcorp-it-support.net&gt;</span>
To: "Target Corp Employee" &lt;employee@target-corp.com&gt;
Subject: Action Required: Your Single Sign-On (SSO) Password Expires in 24 Hours!
Date: Tue, 10 Feb 2026 15:22:15 +0000
<span class="header-clickable" data-field="msgid">Message-ID: &lt;SSO-RESET-93820-2026-IT@targetcorp-it-support.net&gt;</span>
MIME-Version: 1.0`,

        `Return-Path: <delivery-notification@dhl-tracking-alert.com>
Received: from mail.dhl-tracking-alert.com (mail.dhl-tracking-alert.com [198.51.100.180])
        by mx.corporate-mail-gateway.com with ESMTPS id z12si384910plk.14.2026.02.10.08.41.05
        for &lt;employee@target-corp.com&gt;;
        Tue, 10 Feb 2026 08:41:07 -0800 (PST)
<span class="header-clickable" data-field="spf">Received-SPF: pass</span> (mx.corporate-mail-gateway.com: domain of delivery-notification@dhl-tracking-alert.com designates 198.51.100.180 as permitted sender) client-ip=198.51.100.180;
<span class="header-clickable" data-field="auth">Authentication-Results: mx.corporate-mail-gateway.com;</span>
       spf=pass (sender IP is 198.51.100.180) smtp.mailfrom=delivery-notification@dhl-tracking-alert.com;
       dkim=pass header.i=@dhl-tracking-alert.com header.s=dhlkey;
       dmarc=pass (p=QUARANTINE sp=NONE dis=NONE) header.from=dhl-tracking-alert.com
<span class="header-clickable" data-field="from">From: "DHL Express Delivery" &lt;delivery-notification@dhl-tracking-alert.com&gt;</span>
To: "Recipient" &lt;employee@target-corp.com&gt;
Subject: Delivery Failed: Important parcel delivery outstanding - Action required!
Date: Tue, 10 Feb 2026 16:41:00 +0000
<span class="header-clickable" data-field="msgid">Message-ID: &lt;DHL-TRACK-99420-EXP-2026@dhl-tracking-alert.com&gt;</span>
MIME-Version: 1.0`,

        `Return-Path: <no-reply@sharepoint-docs-portal.com>
Received: from mail.sharepoint-docs-portal.com (mail.sharepoint-docs-portal.com [198.51.100.82])
        by mx.corporate-mail-gateway.com with ESMTPS id s12si948291plh.10.2026.02.10.09.12.30
        for <employee@target-corp.com>;
        Tue, 10 Feb 2026 09:12:31 -0800 (PST)
<span class="header-clickable" data-field="spf">Received-SPF: pass</span> (mx.corporate-mail-gateway.com: domain of no-reply@sharepoint-docs-portal.com designates 198.51.100.82 as permitted sender) client-ip=198.51.100.82;
<span class="header-clickable" data-field="auth">Authentication-Results: mx.corporate-mail-gateway.com;</span>
       spf=pass (sender IP is 198.51.100.82) smtp.mailfrom=no-reply@sharepoint-docs-portal.com;
       dkim=pass header.i=@sharepoint-docs-portal.com header.s=default;
       dmarc=pass (p=QUARANTINE sp=NONE dis=NONE) header.from=sharepoint-docs-portal.com
<span class="header-clickable" data-field="from">From: "Microsoft SharePoint Online" &lt;no-reply@sharepoint-docs-portal.com&gt;</span>
To: "Colleague" &lt;employee@target-corp.com&gt;
Subject: Urgent: Corporate Payroll adjustments shared with you
Date: Tue, 10 Feb 2026 17:12:28 +0000
<span class="header-clickable" data-field="msgid">Message-ID: &lt;SP-SHARE-930219-EXP-2026@sharepoint-docs-portal.com&gt;</span>
MIME-Version: 1.0`,

        `Return-Path: <benefits@targetcorp-hr-portal.com>
Received: from mail.targetcorp-hr-portal.com (mail.targetcorp-hr-portal.com [198.51.100.125])
        by mx.corporate-mail-gateway.com with ESMTPS id h15si942918plh.14.2026.02.10.10.05.22
        for <employee@target-corp.com>;
        Tue, 10 Feb 2026 10:05:24 -0800 (PST)
<span class="header-clickable" data-field="spf">Received-SPF: pass</span> (mx.corporate-mail-gateway.com: domain of benefits@targetcorp-hr-portal.com designates 198.51.100.125 as permitted sender) client-ip=198.51.100.125;
<span class="header-clickable" data-field="auth">Authentication-Results: mx.corporate-mail-gateway.com;</span>
       spf=pass (sender IP is 198.51.100.125) smtp.mailfrom=benefits@targetcorp-hr-portal.com;
       dkim=pass header.i=@targetcorp-hr-portal.com header.s=default;
       dmarc=pass (p=QUARANTINE sp=NONE dis=NONE) header.from=targetcorp-hr-portal.com
<span class="header-clickable" data-field="from">From: "Target Corp HR Department" &lt;benefits@targetcorp-hr-portal.com&gt;</span>
To: "Target Corp Employee" &lt;employee@target-corp.com&gt;
Subject: Urgent Notice: Open Enrollment Deadline expires today!
Date: Tue, 10 Feb 2026 18:05:20 +0000
<span class="header-clickable" data-field="msgid">Message-ID: &lt;HR-ENROLL-93821-2026@targetcorp-hr-portal.com&gt;</span>
MIME-Version: 1.0`,

        `Return-Path: <billing@globalparts-logistics.net>
Received: from mail.globalparts-logistics.net (mail.globalparts-logistics.net [203.0.113.14])
        by mx.corporate-mail-gateway.com with ESMTPS id v12si948192plg.24.2026.02.10.11.10.12
        for <employee@target-corp.com>;
        Tue, 10 Feb 2026 11:10:15 -0800 (PST)
<span class="header-clickable" data-field="spf">Received-SPF: pass</span> (mx.corporate-mail-gateway.com: domain of billing@globalparts-logistics.net designates 203.0.113.14 as permitted sender) client-ip=203.0.113.14;
<span class="header-clickable" data-field="auth">Authentication-Results: mx.corporate-mail-gateway.com;</span>
       spf=pass (sender IP is 203.0.113.14) smtp.mailfrom=billing@globalparts-logistics.net;
       dkim=pass header.i=@globalparts-logistics.net header.s=default;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=globalparts-logistics.net
<span class="header-clickable" data-field="from">From: "Accounts Receivable - Global Parts" &lt;billing@globalparts-logistics.net&gt;</span>
To: "Accounts Payable" &lt;employee@target-corp.com&gt;
Subject: Overdue Invoice #AP-938291: Immediate payment required
Date: Tue, 10 Feb 2026 19:10:10 +0000
<span class="header-clickable" data-field="msgid">Message-ID: &lt;INV-OVERDUE-AP938291@globalparts-logistics.net&gt;</span>
MIME-Version: 1.0`,

        `Return-Path: <incident-response@targetcorp-alert.com>
Received: from mail.targetcorp-alert.com (mail.targetcorp-alert.com [192.0.2.118])
        by mx.corporate-mail-gateway.com with ESMTPS id c12si938201plh.42.2026.02.10.12.30.18
        for <employee@target-corp.com>;
        Tue, 10 Feb 2026 12:30:20 -0800 (PST)
<span class="header-clickable" data-field="spf">Received-SPF: pass</span> (mx.corporate-mail-gateway.com: domain of incident-response@targetcorp-alert.com designates 192.0.2.118 as permitted sender) client-ip=192.0.2.118;
<span class="header-clickable" data-field="auth">Authentication-Results: mx.corporate-mail-gateway.com;</span>
       spf=pass (sender IP is 192.0.2.118) smtp.mailfrom=incident-response@targetcorp-alert.com;
       dkim=pass header.i=@targetcorp-alert.com header.s=default;
       dmarc=pass (p=QUARANTINE sp=NONE dis=NONE) header.from=targetcorp-alert.com
<span class="header-clickable" data-field="from">From: "Target Corp Cyber Security Response" &lt;incident-response@targetcorp-alert.com&gt;</span>
To: "Employee" &lt;employee@target-corp.com&gt;
Subject: Crucial Security Action: Corporate Data Breach - Password reset required
Date: Tue, 10 Feb 2026 20:30:15 +0000
<span class="header-clickable" data-field="msgid">Message-ID: &lt;SEC-BREACH-INC2026-9382@targetcorp-alert.com&gt;</span>
MIME-Version: 1.0`,

        `Return-Path: <security@chase-verification-service.com>
Received: from mail.chase-verification-service.com (mail.chase-verification-service.com [198.51.100.198])
        by mx.corporate-mail-gateway.com with ESMTPS id b12si948291plk.72.2026.02.10.13.24.05
        for <employee@target-corp.com>;
        Tue, 10 Feb 2026 13:24:07 -0800 (PST)
<span class="header-clickable" data-field="spf">Received-SPF: pass</span> (mx.corporate-mail-gateway.com: domain of security@chase-verification-service.com designates 198.51.100.198 as permitted sender) client-ip=198.51.100.198;
<span class="header-clickable" data-field="auth">Authentication-Results: mx.corporate-mail-gateway.com;</span>
       spf=pass (sender IP is 198.51.100.198) smtp.mailfrom=security@chase-verification-service.com;
       dkim=pass header.i=@chase-verification-service.com header.s=default;
       dmarc=pass (p=QUARANTINE sp=NONE dis=NONE) header.from=chase-verification-service.com
<span class="header-clickable" data-field="from">From: "Chase Bank Commercial Alert" &lt;security@chase-verification-service.com&gt;</span>
To: "Recipient" &lt;employee@target-corp.com&gt;
Subject: Security Restriction: Suspicious login blocked - Identity verification
Date: Tue, 10 Feb 2026 21:24:00 +0000
<span class="header-clickable" data-field="msgid">Message-ID: &lt;CHASE-RESTRICT-99420@chase-verification-service.com&gt;</span>
MIME-Version: 1.0`,

        `Return-Path: <signature-desk@docusign-verification.net>
Received: from mail.docusign-verification.net (mail.docusign-verification.net [198.51.100.220])
        by mx.corporate-mail-gateway.com with ESMTPS id d12si948291plh.42.2026.02.10.14.05.18
        for <employee@target-corp.com>;
        Tue, 10 Feb 2026 14:05:20 -0800 (PST)
<span class="header-clickable" data-field="spf">Received-SPF: pass</span> (mx.corporate-mail-gateway.com: domain of signature-desk@docusign-verification.net designates 198.51.100.220 as permitted sender) client-ip=198.51.100.220;
<span class="header-clickable" data-field="auth">Authentication-Results: mx.corporate-mail-gateway.com;</span>
       spf=pass (sender IP is 198.51.100.220) smtp.mailfrom=signature-desk@docusign-verification.net;
       dkim=pass header.i=@docusign-verification.net header.s=default;
       dmarc=pass (p=QUARANTINE sp=NONE dis=NONE) header.from=docusign-verification.net
<span class="header-clickable" data-field="from">From: "DocuSign Signature Service" &lt;signature-desk@docusign-verification.net&gt;</span>
To: "Candidate" &lt;employee@target-corp.com&gt;
Subject: Urgent: Signature Required - Mutual NDA and Retention Agreement
Date: Tue, 10 Feb 2026 22:05:15 +0000
<span class="header-clickable" data-field="msgid">Message-ID: &lt;DOCUSIGN-SIGN-93820-2026@docusign-verification.net&gt;</span>
MIME-Version: 1.0`,

        `Return-Path: <no-reply@zoom-briefing-alert.us>
Received: from mail.zoom-briefing-alert.us (mail.zoom-briefing-alert.us [203.0.113.42])
        by mx.corporate-mail-gateway.com with ESMTPS id z42si854932pld.12.2026.02.10.14.42.12
        for &lt;employee@target-corp.com&gt;;
        Tue, 10 Feb 2026 14:42:15 -0800 (PST)
<span class="header-clickable" data-field="spf">Received-SPF: pass</span> (mx.corporate-mail-gateway.com: domain of no-reply@zoom-briefing-alert.us designates 203.0.113.42 as permitted sender) client-ip=203.0.113.42;
<span class="header-clickable" data-field="auth">Authentication-Results: mx.corporate-mail-gateway.com;</span>
       spf=pass (sender IP is 203.0.113.42) smtp.mailfrom=no-reply@zoom-briefing-alert.us;
       dkim=pass header.i=@zoom-briefing-alert.us header.s=default;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=zoom-briefing-alert.us
<span class="header-clickable" data-field="from">From: "Zoom Meeting Alerter" &lt;no-reply@zoom-briefing-alert.us&gt;</span>
To: "Employee" &lt;employee@target-corp.com&gt;
Subject: Action Required: Mandatory Q2 Corporate Reorganization Briefing - Zoom Link
Date: Tue, 10 Feb 2026 22:42:10 +0000
<span class="header-clickable" data-field="msgid">Message-ID: &lt;ZOOM-BRIEFING-93821-2026@zoom-briefing-alert.us&gt;</span>
MIME-Version: 1.0`,

        `Return-Path: <teams-chat-alert@microsoft-teams-corporate.com>
Received: from mail.microsoft-teams-corporate.com (mail.microsoft-teams-corporate.com [192.0.2.145])
        by mx.corporate-mail-gateway.com with ESMTPS id t15si942918plh.10.2026.02.10.15.15.22
        for <employee@target-corp.com>;
        Tue, 10 Feb 2026 15:15:24 -0800 (PST)
<span class="header-clickable" data-field="spf">Received-SPF: pass</span> (mx.corporate-mail-gateway.com: domain of teams-chat-alert@microsoft-teams-corporate.com designates 192.0.2.145 as permitted sender) client-ip=192.0.2.145;
<span class="header-clickable" data-field="auth">Authentication-Results: mx.corporate-mail-gateway.com;</span>
       spf=pass (sender IP is 192.0.2.145) smtp.mailfrom=teams-chat-alert@microsoft-teams-corporate.com;
       dkim=pass header.i=@microsoft-teams-corporate.com header.s=default;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=microsoft-teams-corporate.com
<span class="header-clickable" data-field="from">From: "Microsoft Teams System Alert" &lt;teams-chat-alert@microsoft-teams-corporate.com&gt;</span>
To: "Target Corp Employee" &lt;employee@target-corp.com&gt;
Subject: System Notification: Direct mention in Target Corp HR-Private channel
Date: Tue, 10 Feb 2026 23:15:20 +0000
<span class="header-clickable" data-field="msgid">Message-ID: &lt;TEAMS-MENTION-93822-2026@microsoft-teams-corporate.com&gt;</span>
MIME-Version: 1.0`,

        `Return-Path: <comments-noreply@googledocs-security-collaboration.com>
Received: from mail.googledocs-security-collaboration.com (mail.googledocs-security-collaboration.com [198.51.100.245])
        by mx.corporate-mail-gateway.com with ESMTPS id g12si948291plk.84.2026.02.10.15.50.05
        for <employee@target-corp.com>;
        Tue, 10 Feb 2026 15:50:07 -0800 (PST)
<span class="header-clickable" data-field="spf">Received-SPF: pass</span> (mx.corporate-mail-gateway.com: domain of comments-noreply@googledocs-security-collaboration.com designates 198.51.100.245 as permitted sender) client-ip=198.51.100.245;
<span class="header-clickable" data-field="auth">Authentication-Results: mx.corporate-mail-gateway.com;</span>
       spf=pass (sender IP is 198.51.100.245) smtp.mailfrom=comments-noreply@googledocs-security-collaboration.com;
       dkim=pass header.i=@googledocs-security-collaboration.com header.s=default;
       dmarc=pass (p=QUARANTINE sp=NONE dis=NONE) header.from=googledocs-security-collaboration.com
<span class="header-clickable" data-field="from">From: "Google Docs (via Drive)" &lt;comments-noreply@googledocs-security-collaboration.com&gt;</span>
To: "Recipient" &lt;employee@target-corp.com&gt;
Subject: Document Shared: "Salary_Review_and_Bonus_Q2_TargetCorp" - Comment tagged you
Date: Tue, 10 Feb 2026 23:50:00 +0000
<span class="header-clickable" data-field="msgid">Message-ID: &lt;GDRIVE-SHARE-99421@googledocs-security-collaboration.com&gt;</span>
MIME-Version: 1.0`
    ];

    // SMTP Header Field Meanings Glossary
    const headerGlossary = {
        spf: {
            title: "SPF (Sender Policy Framework)",
            desc: "SPF checks if the sending server's IP address (e.g. 198.51.100.42) is permitted to send emails for the domain listed in the 'Return-Path'. In this case, the SPF is a PASS. Attackers register domains like 'paypa1-support.com' and authorize their own servers, passing SPF tests. Passing SPF does NOT prove sender validity!"
        },
        dkim: {
            title: "DKIM Signature Header",
            desc: "DKIM embeds a cryptographic public key in the DNS to verify the message body was not altered in transit. A 'dkim=pass' confirms the message was indeed signed by the domain owner. Attackers set up valid signatures for their lookalike domains to bypass mail security gateways."
        },
        auth: {
            title: "Authentication-Results Header",
            desc: "This block summarizes the checks compiled by the target receiving gateway. It shows SPF status, DKIM signing, and DMARC enforcement. Checking this header allows analysts to immediately isolate domain spoofing status."
        },
        from: {
            title: "From (Message Sender)",
            desc: "This is the visual sender displayed to the employee. Display names can be spoofed trivially. Mismatches between the display domain name (e.g., PayPal) and the physical email routing domain (e.g., paypa1-support.com) represent primary phishing signatures."
        },
        to: {
            title: "To (BCC Recipients)",
            desc: "A header target of 'undisclosed-recipients' indicates that the email was sent as a blind carbon copy (BCC) to hundreds or thousands of target addresses in a mass campaign. Personal, authentic corporate notices are direct and personalized."
        },
        msgid: {
            title: "Message-ID Header",
            desc: "A unique crypt-string identifying the mail sequence. A Message-ID generated by generic public servers (like gmail.com) when the body claims corporate executive authority indicates Business Email Compromise spoofing."
        }
    };

    // Quiz Scenarios
    const quizData = [
        {
            question: "You receive an email from 'Target IT Helpdesk' urging you to keep your password by clicking a button because it expires in 24 hours. What is the SAFEST action?",
            options: [
                "Click the button and follow instructions to avoid account lockout.",
                "Hover over the button. If the URL contains 'targetcorp-it-support.net', it is safe to proceed.",
                "Ignore the link. Inspect the actual domain and type the portal address manually into a fresh browser.",
                "Forward the email to your teammates to warn them."
            ],
            correct: 2,
            explanation: "Authentic IT administrative actions do not ask users to extend passwords via direct email clicks. Typosquatted domains like 'targetcorp-it-support.net' are registered by attackers. You must navigate to internal corporate portals using pre-established bookmarks or manual keyboard entries."
        },
        {
            question: "When triaging a suspicious email header, you observe: From: 'PayPal Billing' <billing@paypal.com>, but the Return-Path is <admin@billing-support-service.com>. What does this mismatch tell you?",
            options: [
                "The email has passed routing standards and is secure.",
                "The 'From' domain has been spoofed. The actual sending address is recorded in the Return-Path.",
                "The target mail server is down.",
                "The sender is using a valid secondary corporate alias."
            ],
            correct: 1,
            explanation: "The 'From' header is visually custom and easily forged by scripts. The 'Return-Path' (envelope-from) represents the physical address receiving bounce-backs. An identity mismatch between them is a primary signature of brand spoofing."
        },
        {
            question: "As a corporate finance officer, you receive a direct, confidential email from the 'CEO' demanding an urgent manual wire transfer of $45,000 for a sensitive merger. The email requests absolute secrecy. What must you do?",
            options: [
                "Execute the transfer immediately to prevent transactional delays.",
                "Send the forms but delay the bank release for 2 hours.",
                "Perform verbal out-of-band verification via a pre-registered directory phone number before initiating any wire transfer.",
                "Reply to the email asking the CEO to confirm their location."
            ],
            correct: 2,
            explanation: "CEO Fraud/Business Email Compromise (BEC) uses social engineering, fear, authority, and requests for secrecy. You must NEVER bypass corporate verification procedures. Establish verbal confirmation through a pre-registered internal number, never replying to the suspicious email thread."
        },
        {
            question: "Why do phishers frequently archive malicious scripts in ZIP attachments (e.g. 'Certificate_2026.zip') instead of sending executables directly?",
            options: [
                "ZIP compression guarantees a faster delivery speed.",
                "Archiving files helps bypass standard automated security gateway antivirus scanners.",
                "Modern browsers only download compressed formats.",
                "ZIP archives automatically decrypt security keys."
            ],
            correct: 1,
            explanation: "Secure Email Gateways block standalone scripts (.scr, .exe, .lnk) immediately. Attackers use archived packages (.zip, .iso, .7z) to hide malicious code from initial system scans, hoping the user will uncompress and click the files."
        },
        {
            question: "Why is traditional Multi-Factor Authentication (SMS codes or Authenticator apps) vulnerable to reverse-proxy phishing kits (like Evilginx)?",
            options: [
                "SMS networks are shut down in cybersecurity protocols.",
                "The proxy server acts as a middleman, capturing both the password and the session authentication cookie in real time.",
                "SMS codes expire too quickly.",
                "Authenticator apps do not support modern browsers."
            ],
            correct: 1,
            explanation: "Reverse-proxy phishing kits load a real-time bridge. When the user logs in and enters their MFA code, the proxy forwards it to the authentic provider, logs the user in, intercepts the resulting authentication session cookie, and duplicates it. Hardware FIDO2 credentials block this, as they bind to the specific domain name."
        }
    ];

    /* ==========================================================================
       2. UI Tab Switching Logic
       ========================================================================== */

    const navButtons = document.querySelectorAll(".nav-btn");
    const panels = document.querySelectorAll(".tab-panel");

    navButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const targetTab = btn.getAttribute("data-tab");
            
            // Toggle Nav Active state
            navButtons.forEach(b => b.classList.remove("active"));
            btn.classList.add("active");

            // Toggle Panel active states
            panels.forEach(p => p.classList.remove("active"));
            document.getElementById(`tab-${targetTab}`).classList.add("active");
            
            // Custom initializers per tab
            if (targetTab === "header") {
                initHeaderAnalyzer();
            }
        });
    });

    /* ==========================================================================
       3. Sandbox Inbox Simulator Logic
       ========================================================================== */

    let activeEmailId = null;
    const inboxListContainer = document.getElementById("inbox-email-list");
    const revealFlagsBtn = document.getElementById("reveal-flags-btn");
    
    // Render Left Inbox List
    function renderInboxList() {
        inboxListContainer.innerHTML = "";
        emailsData.forEach(mail => {
            const item = document.createElement("div");
            item.className = `inbox-item ${activeEmailId === mail.id ? 'active' : ''}`;
            item.innerHTML = `
                <div class="inbox-meta-row">
                    <span class="inbox-sender-name">${mail.senderName}</span>
                    <span class="inbox-time">${mail.time}</span>
                </div>
                <div class="inbox-subject">${mail.subject}</div>
                <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 2px;">
                    <span class="inbox-snippet">${mail.snippet}</span>
                    <span class="risk-dot ${mail.risk}"></span>
                </div>
            `;
            item.addEventListener("click", () => loadEmailInSandbox(mail.id));
            inboxListContainer.appendChild(item);
        });
    }

    // Load Selected Email into central view
    function loadEmailInSandbox(id) {
        activeEmailId = id;
        renderInboxList(); // Update selected styles
        
        const mail = emailsData[id];
        
        // Populate sender metadata headers
        document.getElementById("email-sender-avatar").textContent = mail.avatar;
        document.getElementById("email-subject").textContent = mail.subject;
        document.getElementById("email-sender-name").textContent = mail.senderName;
        document.getElementById("email-sender-email").textContent = `<${mail.senderEmail}>`;
        document.getElementById("email-time").textContent = mail.time;

        const bodyViewport = document.getElementById("email-content-body");
        bodyViewport.innerHTML = mail.htmlBody;
        bodyViewport.style.backgroundColor = "#ffffff"; // Email client backgrounds are white

        // Close sidebar if open
        document.getElementById("flag-details-sidebar").classList.remove("active");
        
        // Sync flags if toggle is active
        renderFlagsHotspots();
    }

    // Render Absolute Hotspots over email
    function renderFlagsHotspots() {
        const bodyViewport = document.getElementById("email-content-body");
        
        // Remove any existing hotspots
        const existingHotspots = bodyViewport.querySelectorAll(".flag-hotspot");
        existingHotspots.forEach(h => h.remove());

        if (activeEmailId === null || !revealFlagsBtn.checked) return;

        const mail = emailsData[activeEmailId];
        mail.flags.forEach((flag, idx) => {
            const hotspot = document.createElement("div");
            hotspot.className = "flag-hotspot";
            hotspot.textContent = "!";
            hotspot.style.top = `${flag.top}%`;
            hotspot.style.left = `${flag.left}%`;
            
            hotspot.addEventListener("click", (e) => {
                e.stopPropagation();
                showFlagDetails(flag);
            });
            bodyViewport.appendChild(hotspot);
        });
    }

    // Display Flag Triage Details in Sidebar
    function showFlagDetails(flag) {
        const sidebar = document.getElementById("flag-details-sidebar");
        document.getElementById("flag-title").textContent = flag.title;
        document.getElementById("flag-threat-tag").textContent = flag.threat;
        document.getElementById("flag-risk-tag").textContent = `Risk: ${flag.risk}`;
        document.getElementById("flag-desc").textContent = flag.desc;
        document.getElementById("flag-mitigation").textContent = flag.mitigation;
        
        // Add active class for animated entry
        sidebar.classList.add("active");
    }

    // Switch/Checkbox Listener
    revealFlagsBtn.addEventListener("change", renderFlagsHotspots);

    // Close Sidebar Card
    document.getElementById("close-flag-card").addEventListener("click", () => {
        document.getElementById("flag-details-sidebar").classList.remove("active");
    });

    // Load initial empty list
    renderInboxList();

    /* ==========================================================================
       4. SMTP Header Analyzer Logic
       ========================================================================== */

    const headerEmailSelect = document.getElementById("header-email-select");
    const terminalBody = document.getElementById("header-code-block");

    function initHeaderAnalyzer() {
        const selectedIndex = parseInt(headerEmailSelect.value);
        const rawHeaders = rawHeadersData[selectedIndex];
        const mailAuth = emailsData[selectedIndex].auth;
        
        // Output raw block to terminal
        terminalBody.innerHTML = rawHeaders;
        
        // Populate SPF, DKIM, DMARC auth indicators
        updateAuthIndicators(mailAuth);

        // Bind click events on interactive header fields inside pre
        const clickableTokens = terminalBody.querySelectorAll(".header-clickable");
        clickableTokens.forEach(token => {
            token.addEventListener("click", () => {
                const field = token.getAttribute("data-field");
                inspectHeaderField(field);
            });
        });
    }

    function updateAuthIndicators(auth) {
        const spfCard = document.getElementById("card-spf");
        const dkimCard = document.getElementById("card-dkim");
        const dmarcCard = document.getElementById("card-dmarc");

        // SPF Triage
        document.getElementById("spf-value").textContent = auth.spf;
        spfCard.querySelector(".card-status-dot").className = `card-status-dot ${auth.spf.toLowerCase() === 'pass' ? 'pass' : 'fail'}`;

        // DKIM Triage
        document.getElementById("dkim-value").textContent = auth.dkim;
        dkimCard.querySelector(".card-status-dot").className = `card-status-dot ${auth.dkim.toLowerCase() === 'pass' ? 'pass' : 'fail'}`;

        // DMARC Triage
        document.getElementById("dmarc-value").textContent = auth.dmarc;
        dmarcCard.querySelector(".card-status-dot").className = `card-status-dot ${auth.dmarc.toLowerCase() === 'pass' ? 'pass' : 'fail'}`;
    }

    function inspectHeaderField(field) {
        const glossary = headerGlossary[field];
        if (!glossary) return;

        document.getElementById("header-term-name").textContent = glossary.title;
        document.getElementById("header-term-def").textContent = glossary.desc;
    }

    headerEmailSelect.addEventListener("change", initHeaderAnalyzer);

    /* ==========================================================================
       5. Lookalike Domain Typosquatting Checker Logic
       ========================================================================== */

    const domainInput = document.getElementById("domain-input");
    const domainAnalyzeBtn = document.getElementById("domain-analyze-btn");
    const domainReportCard = document.getElementById("domain-report-card");
    const reportDomainName = document.getElementById("report-domain-name");
    const reportRiskBadge = document.getElementById("report-risk-badge");
    const scoreCircle = document.getElementById("score-circle");
    const scoreNum = document.getElementById("score-num");
    const reportIndicatorsList = document.getElementById("report-indicators-list");

    // Static target check domains
    const officialBrandDomains = ["paypal.com", "microsoft.com", "office365.com", "dhl.com", "google.com", "fedex.com"];

    function auditDomain() {
        let domain = domainInput.value.trim().toLowerCase();
        if (!domain) return;

        // Basic normalization: remove protocol headers
        domain = domain.replace(/^(https?:\/\/)?(www\.)?/, "");
        domain = domain.split("/")[0]; // Retain domain root

        let riskScore = 0;
        let findings = [];

        // Heuristics Check 1: Mismatched root keywords spoofing official brands
        const mimicsBrand = officialBrandDomains.find(brand => {
            const brandBase = brand.split(".")[0];
            return domain.includes(brandBase) && domain !== brand;
        });

        if (mimicsBrand) {
            riskScore += 45;
            findings.push({
                test: "Brand Name Mimicry",
                status: "FAIL",
                desc: `The scanned domain contains the corporate brand keyword '${mimicsBrand.split(".")[0]}' but does not map to the official registered server domain '${mimicsBrand}'. This is highly indicative of credential harvesting targets.`
            });
        } else {
            findings.push({
                test: "Brand Alignment Check",
                status: "PASS",
                desc: "No immediate corporate brand name spoof patterns detected."
            });
        }

        // Heuristics Check 2: homoglyphs character switches (numbers replacing letters)
        const homoglyphPattern = /[01]/;
        if (homoglyphPattern.test(domain)) {
            riskScore += 25;
            findings.push({
                test: "Character Substitution (Homoglyphs)",
                status: "FAIL",
                desc: "The domain uses character substitution indicators (like '1' instead of 'l', or '0' instead of 'o'). Human eyes read these as authentic letters, but servers separate the spoofed domain completely."
            });
        } else {
            findings.push({
                test: "Homoglyph Scanning",
                status: "PASS",
                desc: "No high-risk visual character replacements identified."
            });
        }

        // Heuristics Check 3: Subdomain stacking / camouflage depth
        const domainLevels = domain.split(".");
        if (domainLevels.length >= 4) {
            riskScore += 20;
            findings.push({
                test: "Subdomain Stacking (Depth Alert)",
                status: "FAIL",
                desc: `Scanned domain has ${domainLevels.length} routing tiers (e.g. paypal.com.secure-login.net). Attackers use long domains to push the actual host off mobile screens.`
            });
        } else {
            findings.push({
                test: "Domain Tiering Analysis",
                status: "PASS",
                desc: "Routing depth parameters are within secure, standard tiers."
            });
        }

        // Heuristics Check 4: High-Risk generic TLD registries
        const highRiskTlds = [".xyz", ".cc", ".top", ".club", ".click", ".support", ".info", ".net"];
        const matchedTld = highRiskTlds.find(tld => domain.endsWith(tld));
        if (matchedTld) {
            riskScore += 15;
            findings.push({
                test: "TLD Registry Reputation check",
                status: "FAIL",
                desc: `The registry extension '${matchedTld}' is a high-risk TLD. Threat actors prefer cheap, untraceable generic registrars to spin up disposable phishing sites.`
            });
        } else {
            findings.push({
                test: "TLD Registry Reputation check",
                status: "PASS",
                desc: "Domain resolves under standard, highly reputable top-level domain extensions (.com, .org, etc.)."
            });
        }

        // Display results
        riskScore = Math.min(riskScore, 100);
        renderDomainReport(domain, riskScore, findings);
    }

    function renderDomainReport(domain, score, findings) {
        reportDomainName.textContent = domain;
        scoreNum.textContent = `${score}%`;
        
        // Animate stroke circle fill
        const circumference = 2 * Math.PI * 15.9155;
        const fillOffset = circumference - (score / 100) * circumference;
        scoreCircle.style.strokeDasharray = `${(score / 100) * circumference}, ${circumference}`;

        // Set colors based on risk
        let strokeColor = "#10b981"; // Success
        let riskClass = "safe";
        let riskText = "SECURE / TRUSTED";

        if (score >= 60) {
            strokeColor = "#ef4444"; // Red
            riskClass = "crit";
            riskText = "CRITICAL SPAM/PHISH INDICATOR";
        } else if (score >= 20) {
            strokeColor = "#f59e0b"; // Warning
            riskClass = "warn";
            riskText = "SUSPICIOUS THREAT VECTOR";
        }

        scoreCircle.style.stroke = strokeColor;
        reportRiskBadge.textContent = riskText;
        reportRiskBadge.className = `risk-badge ${riskClass}`;

        // Render findings list
        reportIndicatorsList.innerHTML = "";
        findings.forEach(find => {
            const li = document.createElement("li");
            li.innerHTML = `
                <div>
                    <strong>${find.test}</strong>
                    <p style="font-size: 11px; color: var(--color-muted); margin-top: 2px;">${find.desc}</p>
                </div>
                <span class="indicator-status ${find.status.toLowerCase()}">${find.status}</span>
            `;
            reportIndicatorsList.appendChild(li);
        });

        domainReportCard.classList.remove("hidden");
    }

    domainAnalyzeBtn.addEventListener("click", auditDomain);
    
    // Chip triggers
    document.querySelectorAll(".example-chip").forEach(chip => {
        chip.addEventListener("click", () => {
            domainInput.value = chip.getAttribute("data-domain");
            auditDomain();
        });
    });

    /* ==========================================================================
       6. Interactive Security Awareness Quiz Logic
       ========================================================================== */

    let currentQuestionIdx = 0;
    let quizScore = 0;

    const startQuizBtn = document.getElementById("start-quiz-btn");
    const restartQuizBtn = document.getElementById("restart-quiz-btn");
    const nextQuestionBtn = document.getElementById("next-question-btn");
    
    const quizIntro = document.getElementById("quiz-intro");
    const quizGameplay = document.getElementById("quiz-gameplay");
    const quizResults = document.getElementById("quiz-results");
    
    const quizQIndex = document.getElementById("quiz-q-index");
    const quizLiveScore = document.getElementById("quiz-live-score");
    const quizQuestionText = document.getElementById("quiz-question-text");
    const quizOptionsContainer = document.getElementById("quiz-options-container");
    const quizExplanationBox = document.getElementById("quiz-explanation-box");
    const quizProgressFill = document.getElementById("quiz-progress");

    function startQuiz() {
        currentQuestionIdx = 0;
        quizScore = 0;
        quizIntro.classList.add("hidden");
        quizResults.classList.add("hidden");
        quizGameplay.classList.remove("hidden");
        loadQuizQuestion();
    }

    function loadQuizQuestion() {
        quizExplanationBox.classList.add("hidden");
        nextQuestionBtn.disabled = true;

        const currentQ = quizData[currentQuestionIdx];
        
        // Progress UI
        quizQIndex.textContent = `Question ${currentQuestionIdx + 1} of ${quizData.length}`;
        quizLiveScore.textContent = `Score: ${quizScore}/${currentQuestionIdx}`;
        quizProgressFill.style.width = `${((currentQuestionIdx) / quizData.length) * 100}%`;

        // Load text
        quizQuestionText.textContent = currentQ.question;
        
        // Render option buttons
        quizOptionsContainer.innerHTML = "";
        currentQ.options.forEach((opt, idx) => {
            const btn = document.createElement("button");
            btn.className = "quiz-option";
            btn.textContent = opt;
            btn.addEventListener("click", () => selectQuizAnswer(idx, btn));
            quizOptionsContainer.appendChild(btn);
        });
    }

    function selectQuizAnswer(selectedIndex, clickedBtn) {
        const currentQ = quizData[currentQuestionIdx];
        const allOptionBtns = quizOptionsContainer.querySelectorAll(".quiz-option");
        
        // Disable options
        allOptionBtns.forEach(btn => btn.disabled = true);

        const isCorrect = selectedIndex === currentQ.correct;
        if (isCorrect) {
            quizScore++;
            clickedBtn.classList.add("correct");
            document.getElementById("feedback-status-text").textContent = "Threat Mitigated (Correct!)";
            quizExplanationBox.className = "quiz-feedback-box correct";
        } else {
            clickedBtn.classList.add("incorrect");
            // Highlight actual correct
            allOptionBtns[currentQ.correct].classList.add("correct");
            document.getElementById("feedback-status-text").textContent = "Breach Escalated (Incorrect)";
            quizExplanationBox.className = "quiz-feedback-box incorrect";
        }

        // Output explanation
        document.getElementById("quiz-explanation-text").textContent = currentQ.explanation;
        quizExplanationBox.classList.remove("hidden");
        
        // Update progress bar
        quizLiveScore.textContent = `Score: ${quizScore}/${currentQuestionIdx + 1}`;
        quizProgressFill.style.width = `${((currentQuestionIdx + 1) / quizData.length) * 100}%`;
        
        // Enable next button
        nextQuestionBtn.disabled = false;
    }

    function handleNextQuestion() {
        currentQuestionIdx++;
        if (currentQuestionIdx < quizData.length) {
            loadQuizQuestion();
        } else {
            showQuizResults();
        }
    }

    function showQuizResults() {
        quizGameplay.classList.add("hidden");
        quizResults.classList.remove("hidden");

        const pct = (quizScore / quizData.length) * 100;
        document.getElementById("cert-score-text").textContent = `${quizScore} / ${quizData.length} (${pct}%)`;

        const statusLbl = document.getElementById("cert-status-lbl");
        const certFrame = document.getElementById("cert-card");

        if (pct >= 80) {
            statusLbl.textContent = "GRADE: SECURE GRADUATE PASS";
            statusLbl.style.color = "var(--color-success)";
            certFrame.style.borderColor = "var(--color-success)";
        } else {
            statusLbl.textContent = "GRADE: COMPROMISE DETECTED (FAIL)";
            statusLbl.style.color = "var(--color-danger)";
            certFrame.style.borderColor = "var(--color-danger)";
        }
    }

    startQuizBtn.addEventListener("click", startQuiz);
    restartQuizBtn.addEventListener("click", startQuiz);
    nextQuestionBtn.addEventListener("click", handleNextQuestion);
});
