# Simple-File-Storage-Service-FSS

Stage 1: FSS Baseline Analysis and Requirement Violations
Deadline: April 17, 2026

Home

Purpose
The purpose of Stage 1 is to understand the provided baseline system and demonstrate how it fails to satisfy one or more requirements (R1-R12). This stage is not about fixing the system. It is about learning how to read code, reason about protocol behavior, and connect concrete attacks to requirement violations.

You are expected to work from the provided client, MITM, and server code, together with the project documentation.

During Stage 1, your group should:

study the provided baseline code and understand how the client, MITM, and server interact;
identify attack vectors in the baseline system;
determine which project requirement(s) each attack violates;
demonstrate those attacks concretely using the provided environment;
document your findings in a required template format.
Your goal is not to list every possible bug. Your goal is to identify and demonstrate distinct attack vectors that lead to requirement violations.

Distinctness of Attacks
Stage 1 is scored based on distinct attack vectors, not raw count of submitted entries. An attack is distinct from others when it is grounded in a unique flaw in the code. An easy way to think about is this way: will patching an attack also lead to the patching of another? If yes, then they are not distinct attacks. Similarly, changing filenames, usernames, parameter values, or small details does not automatically make two attacks distinct. Attacks may be treated as the same vector if they rely on the same underlying weakness and demonstrate essentially the same kind of requirement violation. For grading, the final qualification of distinctness is determined by the instructor. If in doubt, ask. 

Required Format for Findings
You will report attack vectors using a findings memo. The memo will contain an entry for each finding in a fixed templated format containing:

Finding ID: Use a unique identifier such as F-01, F-02, F-03, and so on.
Title: Provide a short descriptive title for the attack.
Violated requirement(s): List the project requirement number or numbers violated by the attack.
Severity: You interpretation of the severity of the violation; use Low, Medium, High, or Critical
Attack steps: Attack steps must be concrete, reproducible actions that another group or the instructor can follow directly using the submitted scripts and the provided environment. Attack steps must not rely on missing explanation, implied behavior, or unstated manual intervention. See examples.
Evidence: Evidence must state what observable result demonstrates the claimed requirement violation. Evidence should describe what the reviewer should see after performing the attack steps. It should be specific enough that another person can determine whether the attack succeeded.
You should not be verbose, but specific. Here are two example entries.

Finding ID: F-01
Title: Upload content can be changed in transit
Violated requirement(s): R5
Severity: High

Attack steps:
1. Run python3 server.py in server shell
2. Run python3 mitm_F01.py in MITM shell
3. Run python3 client.py in client shell
4. Log in as alice
5. Upload notes.txt with content 'hello'
6. Download notes.txt

Evidence:
The contents field in the download differ from what alice originally entered for upload.
Finding ID: F-02
Title: Replay of upload causes unintended second write
Violated requirement(s): R4, R8
Severity: High

Attack steps:
1. Run python3 server.py in server shell.
2. Run python3 mitm_F02.py in MITM shell.
3. Run python3 client.py in client shell.
4. Log in as alice.
5. Upload notes.txt with content 'hello'.
6. Download notes.txt.

Evidence:
Timestamp in step 6 response is different from step 5 response.
Note that each attack here refers to a modified version of mitm.py that carries out the attack. So, for any finding that depends on modified MITM behavior, there must be a corresponding attack script (modified mitm.py). You can also provide other scripts to be run in the MITM machine as part of an attack. In either case, you cannot ask the reviewer to write the scripts. Modified mitm.py should be named as mitm_F[finding number].py.

Keep attack scripts specific to a finding. Do not put all attacks in one modified file. This also helps others to see the precise steps that an attack needs to take.

Deliverables
Your Stage 1 submission must contain the following:

Findings Memo: Submit a text file containing one finding entry per attack you wish to report. Each entry must contain the entries stated before.
Attack Scripts: Submit a zip archive containing the attack scripts used for your findings, clearly identifying which finding a script applies to; e.g. mitm_F05.py, supplement_F03.py, and such.
Submission Expectations
A valid submission must satisfy all of the following:   

every reported finding must identify at least one requirement violation;
every reported finding must be reproducible from the submitted attack steps;
wherever applicable, a reported finding must have a corresponding script in the zip archive;
the memo and attack scripts must use matching finding IDs.
A strong submission will:

focus on distinct attack ideas rather than shallow variants,
tie each attack clearly to one or more requirements,
use concrete, minimal reproduction steps, and
describe evidence in terms of what can actually be observed.
A weak submission will:

list many minor variants of the same issue,
provide vague steps, or
name requirements without clearly showing the violation.
Grading
Stage 1 is graded out of 100 points.

Distinct attack vectors: 60 points. Each distinct valid attack vector is worth 5 points, up to a maximum of 60 points. This means that demonstrating 12 distinct valid attack vectors earns full credit for this portion.
Quality of findings submission: 40 points. Up to 40 points are awarded for submission quality, including:
correct requirement mapping,
reproducible attack steps,
evidence that actually demonstrates the claimed violation, and
overall clarity and organization.
Keep in mind that Stage 1 is not a complete security audit of everything that could possibly go wrong. You are not expected to fix the baseline system in this stage. You are expected to understand it well enough so that you can fix it in Stage 2.

## Project Overview

GR Project: Simple File Storage Service (FSS)
Upcoming Project Deadlines
Group formation due: April 2, 2026 (before class)
Stage 1 due: April 17, 2026
Stage 2 due: Part A - May 1, 2026; Part B - May 15, 2026
Stage 3 due: May 28, 2026
Stage 4 due: June 4, 2026
QUICK LINKS:  Stage 1    Stage 2    Stage 3    Stage 4

Project Overview
In this project, you will analyze, attack, and harden a deliberately insecure file storage service. The system includes a client, a server, and a transparent man-in-the-middle (MITM) node. The goal is to make it secure against realistic attacks under an active network adversary model.

The baseline implementation is intentionally weak. Across four stages, you will progressively study the system, exploit its weaknesses, and redesign it to resist those attacks.

This is a security engineering project, not a feature-building exercise. You will be evaluated on the quality of your threat analysis, the soundness of your design choices, the correctness of your implementation, and the clarity with which you justify security decisions.

What the File Storage Service Does
The baseline system is a multi-user file storage service. A user connects to the server and can then:

log in
list files in their own storage directory
upload a file into their own storage directory
download a file from their own storage directory
log out
Each authenticated user has a directory under the server's storage area. The server uses a users.json file to load account credentials. Few accounts are present there for baseline demonstration.

The baseline implementation is deliberately insecure. It may appear functional under normal conditions, but it is not designed to withstand active attacks.

Client Menu and Supported Commands
When run, the client presents the following menu:

Login
Create account
List files
Upload file
Download file
Logout
Quit
Login
Prompts for username and password. If successful, the server returns a session token.

Create account
Prompts for a new username and password and creates an account.

List files
Lists the files in the authenticated user’s storage directory. For each file, the server returns:

filename
modification timestamp
SHA-256 digest
Upload file
Prompts for a filename and multiline content. The file is stored on the server. The server returns:

success/error
a completion message
modification timestamp
SHA-256 digest
Download file
Prompts for a filename. The server returns:

filename
full file content
modification timestamp
SHA-256 digest
Logout
Sends a logout request for the current token.

Quit
Exits the client.

Communication Format: JSON over TCP
The client and server communicate using newline-delimited JSON over a TCP socket.

This means:

each request is a single JSON object
each response is a single JSON object
each JSON object is terminated by a newline \n
the receiver reads until newline, then parses the JSON
So the protocol is application-layer JSON messaging, not HTTP. You are not permitted to change the messaging format, but can add additional keys to the JSON structures. Since JSON is a text-based format, any binary data must also be appropriately encoded. Any change to the structures below must be documented in your redesign; secrecy of the structure cannot be a means to security.

Request Structure
Every request is a JSON object with at least an action field.

```json
CREATE request
{
  "action": "CREATE",
  "username": "<username>",
  "password": "<password>"
}
AUTH request
{
  "action": "AUTH",
  "username": "<username>",
  "password": "<password>"
}
LIST request
{
  "action": "LIST",
  "token": "<session_token>"
}
UPLOAD request
{
  "action": "UPLOAD",
  "token": "<session_token>",
  "filename": "<filename>",
  "content": "<file contents>"
}
DOWNLOAD request
{
  "action": "DOWNLOAD",
  "token": "<session_token>",
  "filename": "<filename>"
}
LOGOUT request
{
  "action": "LOGOUT",
  "token": "<session_token>"
}

```

Response Structure
Every response is also a JSON object. At minimum, responses include:

"status": "ok" on success, or
"status": "error" on failure
Most error responses also include a message field.

```json
CREATE success
{
  "status": "ok",
  "token": "account created"
}
AUTH success
{
  "status": "ok",
  "token": "<session_token>"
}
LIST success
{
  "status": "ok",
  "files": [
    {
      "name": "<filename>",
      "modified_ts": <timestamp>,
      "digest": "<sha256 digest>"
    },
    ...
  ]
}
UPLOAD success
{
  "status": "ok",
  "message": "upload complete for <username>",
  "ts": <timestamp>,
  "sha256": "<sha256 digest>"
}
DOWNLOAD success
{
  "status": "ok",
  "filename": "<filename>",
  "content": "<file contents>",
  "modified_ts": <timestamp>,
  "sha256": "<sha256 digest>"
}
LOGOUT success
{
  "status": "ok",
  "message": "<username> logged out"
}
Generic error
{
  "status": "error",
  "message": "<error description>"
}
```json

What to Download
Download the project starter package HERE Download HERE.

Starter materials

client_root/
server_root/
mitm_root/
setup_net
enter
In addition, this page and linked information here serves as the primary documentation.

How to Run the Project
This project is intended to run inside a Linux environment. While it should work in any modern Linux environment, it has only been tested in the class VM. If you run it in another VM but run into problems, switch to the class VM in order stay on time. Also, working in the same VM creates a uniform platform for other groups who will evaluate your design later; otherwise, you will have to provide environment documentation as well.

Step 1: Create the namespace environment
From the project root (home directory assumed below):

student@student-vm:~$ chmod u+x setup_net
student@student-vm:~$ sudo ./setup_net
This creates three Linux network namespaces Links to an external site.:

ns_client: the network where the client runs 
ns_mitm: an intermediate network through which all traffic between the client and the server pass through
ns_server: the network where the server runs
You need to run this script every time the VM is restarted. 

Step 2: Enter each environment
Use the enter helper script to open a shell in the client, server, or the intermediate MITM machine. For example:

student@student-vm:~$ chmod u+x enter
student@student-vm:~$ sudo ./enter server
root@server:~# ls
server.py  server_storage  users.json
Use three terminals to open a shell for each.

Step 3: Run the programs
In the server shell:

root@server:~# python3 server.py
In the MITM shell:

root@mitm:~# python3 mitm.py
In the client shell:

root@client:~# python3 client.py
It is advised that you create Python virtual environments and run the programs from within. That way you can later supply a requirements.txt file for the packages one needs to install your modified versions.

Threat Model and Requirements
Assume the network is adversarial. Malicious clients or intermediate network nodes may attempt to observe, alter, replay, inject, suppress, or misuse protocol messages, or may attempt to access user files and interfere with normal service operation. For the scope of this project, the following requirements (R1-R12) define the security-related expectations of the system.

R1. Only a user entitled to a file should be able to view its contents.

R2. An honest user should be able to carry out file operations on files they are permitted to use.

R3. The system should produce a clear and consistent outcome for each request.

R4. A completed operation should correspond to a current request from an honest user.

R5. A completed operation should reflect an honest user’s intended operation.

R6. A client should accept a service response only when that response genuinely corresponds to its request.

R7. A user should not be able to access, alter, or remove files they are not permitted to use.

R8. Information produced or exchanged in one interaction should be usable only within its intended session.

R9. Invalid, unexpected, or malformed input should not cause unsafe behavior.

R10. Ordinary misuse of the protocol should not trivially prevent legitimate use by others within the project environment.

R11. The system should leave enough evidence of important events and failures to support later review and debugging.

R12. Any trust necessary for correct behavior must be explicitly established by the system.

Much of what you will design and evaluate in this project will be with respect to these 12 expectations. While you may identify other sensible requirements, grading will be strictly with respect to the ones stated above.

Groups and Individual Contributions
Each group will have four members. Adjustments will be done by the instructor to account for uneven number of students enrolled in the course. Each group member is expected to participate in all stages. 

Project work in this course is group-based, and the default assumption is that all group members receive the group's project score. However, substantial contribution imbalance within a group may lead to individual grade adjustments. As part of Stage 4 evaluation, each student will complete a confidential peer-contribution form rating the contributions of the other members of their group. These ratings are intended to identify serious outliers in contribution, not to regrade the project independently. If the feedback indicates a substantial and consistent contribution imbalance, individual project grades may be adjusted accordingly. This process is intended to support fair group grading while keeping the project itself collaborative. 

Groups must be formed by April 2, 2026 (second day of class, before class). If you have a group of four, send an email to the instructor with the group member names. For students who have not joined a group by then, the instructor will make the group assignment and announce in class. 

It is imperative group formation is not delayed since the Stage 1 deadline in close.

Project Stages
The project will advance in four stages, each with its own deliverables, deadlines, and grading. The final score for the project will be a weighted sum of the scores from each stage. The weights are given below in parenthesis.

Stage 1 (20%): study the baseline implementation and demonstrate how it fails one or more requirements
Stage 2 (40%): propose and implement a revised version to meet failing requirements
Stage 3 (20%): perform a security review of another group's design
Stage 4 (20%): present a revision plan based on review, as well as project-level reflections
Details on each stage are available in the linked pages.

Deliverables
Each stage has its own deliverables and submission requirements. Depending on the stage, you may be required to submit design files, code, structured attack memos, or attack scripts. Consult the individual stage page for exact details.

Deadlines
Stage 1 due: April 17, 2026

Stage 2 due: Part A - May 1, 2026; Part B - May 15, 2026

Stage 3 due: May 28, 2026

Stage 4 due: June 4, 2026

Note that this is not just an exercise in coding skills, but also on the ability to work in a multi-group environments and communicate findings to other groups. Specifically, outputs of Stage 2 and Stage 3 are vital for other groups to proceed. Therefore, meeting the deadlines is critical.

What Packages Are Allowed
You may use standard cryptographic primitives from common Python libraries, but the actual implementation of the security guarantees has to be fully in the application layer code that you write. This means that you cannot wrap a network connection in Python's TLS implementation, or adopt a prebuilt secure transport wrapper. In fact, even doing so would leave many requirements unaddressed. You may draw on ideas from existing protocols, including TLS, and are encouraged to do so. If you have doubts on whether a certain package is allowed, ask the instructor early on. 

Keying Material
Secrets are vital components of network protocols based on cryptographic approaches. However, management of these secrets is a problem in itself. You cannot assume that secrets are "just" present for use in the system. For example, users of the service create accounts and use login/passwords to authenticate. You can store the passwords in a secure form to make trivial attacks infeasible. However, if you also require a shared secret to be present, then the establishment of that secret must be performed by your protocol, as well its proper management. Failure to do so is actually a violation of requirement R12.

Similarly, Public Key Infrastructure is a critical asset in today's network security. Each of the client, server, and MITM nodes contain the /certs folder with two certificates. These certificates represent the globally recognized trusted root CAs within the project. Each group may request up to two certificates signed by the provided trusted root CAs at no cost. Send a X.509 CSR file to the instructor to obtain the certificates, along with a description of who it is for and the purpose for which it will be used. This allowance applies per group, not per student. This does not prevent you from creating your CA for the service, but failure to incorporate certificate management then may violate some requirements. Any additional certificate request will incur a 3-point deduction per certificate in the Stage 2 scores, including reissuance caused by CSR mistakes, incorrect certificate details, or other preventable errors. Plan carefully before requesting certificates. 

So, do not take secrets for granted, as something you copy-paste from one file to another. Plan around its management.

Final Notes
Treat the early stages seriously. The strongest solutions usually come from groups that understand the system deeply before trying to secure it.

Do not patch blindly. Preserve functionality, justify your security choices, and validate your defenses against realistic attacks.