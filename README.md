# Simple File Storage Service (FSS)

**Stage 1:** FSS Baseline Analysis and Requirement Violations  
**Deadline:** April 17, 2026

## Contents

- [Stage 1 Overview](#stage-1-overview)
- [Project Overview](#project-overview)
- [Client Menu and Commands](#client-menu-and-commands)
- [Communication Format](#communication-format)
- [How to Run the Project](#how-to-run-the-project)
- [Threat Model and Requirements](#threat-model-and-requirements)
- [Project Stages](#project-stages)
- [Keying Material](#keying-material)

## Stage 1 Overview

### Purpose

The purpose of Stage 1 is to understand the provided baseline system and
demonstrate how it fails to satisfy one or more requirements (R1-R12). This
stage is not about fixing the system. It is about learning how to read code,
reason about protocol behavior, and connect concrete attacks to requirement
violations.

You are expected to work from the provided client, MITM, and server code,
together with the project documentation.

During Stage 1, your group should:

- Study the provided baseline code and understand how the client, MITM, and
  server interact.
- Identify attack vectors in the baseline system.
- Determine which project requirement(s) each attack violates.
- Demonstrate those attacks concretely using the provided environment.
- Document your findings in the required template format.

Your goal is not to list every possible bug. Your goal is to identify and
demonstrate distinct attack vectors that lead to requirement violations.

### Distinctness of Attacks

Stage 1 is scored based on distinct attack vectors, not raw count of submitted
entries. An attack is distinct from others when it is grounded in a unique flaw
in the code.

A useful test is: would patching this attack also patch another submitted
attack? If yes, then they are not distinct attacks. Changing filenames,
usernames, parameter values, or small details does not automatically make two
attacks distinct.

Attacks may be treated as the same vector if they rely on the same underlying
weakness and demonstrate essentially the same kind of requirement violation. For
grading, the final qualification of distinctness is determined by the
instructor. If in doubt, ask.

## Required Format for Findings

Report attack vectors using a findings memo. The memo must contain one entry per
finding in this fixed template:

| Field | Description |
| --- | --- |
| Finding ID | Use a unique identifier such as `F-01`, `F-02`, `F-03`, and so on. |
| Title | Provide a short descriptive title for the attack. |
| Violated requirement(s) | List the project requirement number or numbers violated by the attack. |
| Severity | Your interpretation of the severity of the violation: `Low`, `Medium`, `High`, or `Critical`. |
| Attack steps | Concrete, reproducible actions that another group or the instructor can follow directly using the submitted scripts and provided environment. |
| Evidence | The observable result that demonstrates the claimed requirement violation. |

Attack steps must not rely on missing explanation, implied behavior, or unstated
manual intervention. Evidence should be specific enough that another person can
determine whether the attack succeeded.

Be specific, not verbose.

### Example Finding: F-01

**Finding ID:** F-01  
**Title:** Upload content can be changed in transit  
**Violated requirement(s):** R5  
**Severity:** High

**Attack steps:**

1. Run `python3 server.py` in the server shell.
2. Run `python3 mitm_F01.py` in the MITM shell.
3. Run `python3 client.py` in the client shell.
4. Log in as `alice`.
5. Upload `notes.txt` with content `hello`.
6. Download `notes.txt`.

**Evidence:**

The contents field in the download differs from what `alice` originally entered
for upload.

### Example Finding: F-02

**Finding ID:** F-02  
**Title:** Replay of upload causes unintended second write  
**Violated requirement(s):** R4, R8  
**Severity:** High

**Attack steps:**

1. Run `python3 server.py` in the server shell.
2. Run `python3 mitm_F02.py` in the MITM shell.
3. Run `python3 client.py` in the client shell.
4. Log in as `alice`.
5. Upload `notes.txt` with content `hello`.
6. Download `notes.txt`.

**Evidence:**

Timestamp in step 6 response is different from step 5 response.

Each attack above refers to a modified version of `mitm.py` that carries out the
attack. For any finding that depends on modified MITM behavior, there must be a
corresponding attack script. You can also provide other scripts to be run in the
MITM machine as part of an attack. In either case, do not ask the reviewer to
write the scripts.

Modified `mitm.py` files should be named as `mitm_F[finding number].py`, such as
`mitm_F05.py`.

Keep attack scripts specific to a finding. Do not put all attacks in one
modified file. This also helps others see the precise steps that an attack
needs.

## Stage 1 Deliverables

Your Stage 1 submission must contain:

- **Findings Memo:** A text file containing one finding entry per attack you
  wish to report. Each entry must contain the fields listed above.
- **Attack Scripts:** A zip archive containing the attack scripts used for your
  findings, clearly identifying which finding each script applies to; for
  example, `mitm_F05.py` or `supplement_F03.py`.

### Submission Expectations

A valid submission must satisfy all of the following:

- Every reported finding identifies at least one requirement violation.
- Every reported finding is reproducible from the submitted attack steps.
- Wherever applicable, a reported finding has a corresponding script in the zip
  archive.
- The memo and attack scripts use matching finding IDs.

A strong submission will:

- Focus on distinct attack ideas rather than shallow variants.
- Tie each attack clearly to one or more requirements.
- Use concrete, minimal reproduction steps.
- Describe evidence in terms of what can actually be observed.

A weak submission will:

- List many minor variants of the same issue.
- Provide vague steps.
- Name requirements without clearly showing the violation.

### Grading

Stage 1 is graded out of 100 points.

| Category | Points | Details |
| --- | ---: | --- |
| Distinct attack vectors | 60 | Each distinct valid attack vector is worth 5 points, up to a maximum of 60 points. Demonstrating 12 distinct valid attack vectors earns full credit for this portion. |
| Quality of findings submission | 40 | Awarded for correct requirement mapping, reproducible attack steps, evidence that demonstrates the claimed violation, and overall clarity and organization. |

Stage 1 is not a complete security audit of everything that could possibly go
wrong. You are not expected to fix the baseline system in this stage. You are
expected to understand it well enough so that you can fix it in Stage 2.

## Project Overview

**GR Project:** Simple File Storage Service (FSS)

### Upcoming Project Deadlines

| Milestone | Due date |
| --- | --- |
| Group formation | April 2, 2026, before class |
| Stage 1 | April 17, 2026 |
| Stage 2, Part A | May 1, 2026 |
| Stage 2, Part B | May 15, 2026 |
| Stage 3 | May 28, 2026 |
| Stage 4 | June 4, 2026 |

**Quick links:** Stage 1 | Stage 2 | Stage 3 | Stage 4

In this project, you will analyze, attack, and harden a deliberately insecure
file storage service. The system includes a client, a server, and a transparent
man-in-the-middle (MITM) node. The goal is to make it secure against realistic
attacks under an active network adversary model.

The baseline implementation is intentionally weak. Across four stages, you will
progressively study the system, exploit its weaknesses, and redesign it to
resist those attacks.

This is a security engineering project, not a feature-building exercise. You
will be evaluated on the quality of your threat analysis, the soundness of your
design choices, the correctness of your implementation, and the clarity with
which you justify security decisions.

### What the File Storage Service Does

The baseline system is a multi-user file storage service. A user connects to the
server and can then:

- Log in.
- List files in their own storage directory.
- Upload a file into their own storage directory.
- Download a file from their own storage directory.
- Log out.

Each authenticated user has a directory under the server's storage area. The
server uses a `users.json` file to load account credentials. A few accounts are
present there for baseline demonstration.

The baseline implementation is deliberately insecure. It may appear functional
under normal conditions, but it is not designed to withstand active attacks.

## Client Menu and Commands

When run, the client presents this menu:

1. Login
2. Create account
3. List files
4. Upload file
5. Download file
6. Logout
7. Quit

| Command | What it does | Response includes |
| --- | --- | --- |
| Login | Prompts for username and password. If successful, the server returns a session token. | Session token |
| Create account | Prompts for a new username and password and creates an account. | Account creation status |
| List files | Lists the files in the authenticated user's storage directory. | Filename, modification timestamp, SHA-256 digest |
| Upload file | Prompts for a filename and multiline content. The file is stored on the server. | Success/error, completion message, modification timestamp, SHA-256 digest |
| Download file | Prompts for a filename. | Filename, full file content, modification timestamp, SHA-256 digest |
| Logout | Sends a logout request for the current token. | Logout status |
| Quit | Exits the client. | None |

## Communication Format

The client and server communicate using newline-delimited JSON over a TCP
socket.

This means:

- Each request is a single JSON object.
- Each response is a single JSON object.
- Each JSON object is terminated by a newline, `\n`.
- The receiver reads until newline, then parses the JSON.

The protocol is application-layer JSON messaging, not HTTP. You are not
permitted to change the messaging format, but you can add additional keys to the
JSON structures. Since JSON is a text-based format, any binary data must also be
appropriately encoded.

Any change to the structures below must be documented in your redesign; secrecy
of the structure cannot be a means to security.

### Request Structure

Every request is a JSON object with at least an `action` field.

#### `CREATE` Request

```json
{
  "action": "CREATE",
  "username": "<username>",
  "password": "<password>"
}
```

#### `AUTH` Request

```json
{
  "action": "AUTH",
  "username": "<username>",
  "password": "<password>"
}
```

#### `LIST` Request

```json
{
  "action": "LIST",
  "token": "<session_token>"
}
```

#### `UPLOAD` Request

```json
{
  "action": "UPLOAD",
  "token": "<session_token>",
  "filename": "<filename>",
  "content": "<file contents>"
}
```

#### `DOWNLOAD` Request

```json
{
  "action": "DOWNLOAD",
  "token": "<session_token>",
  "filename": "<filename>"
}
```

#### `LOGOUT` Request

```json
{
  "action": "LOGOUT",
  "token": "<session_token>"
}
```

### Response Structure

Every response is also a JSON object. At minimum, responses include:

- `"status": "ok"` on success.
- `"status": "error"` on failure.

Most error responses also include a `message` field.

#### `CREATE` Success

```json
{
  "status": "ok",
  "token": "account created"
}
```

#### `AUTH` Success

```json
{
  "status": "ok",
  "token": "<session_token>"
}
```

#### `LIST` Success

```json
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
```

#### `UPLOAD` Success

```json
{
  "status": "ok",
  "message": "upload complete for <username>",
  "ts": <timestamp>,
  "sha256": "<sha256 digest>"
}
```

#### `DOWNLOAD` Success

```json
{
  "status": "ok",
  "filename": "<filename>",
  "content": "<file contents>",
  "modified_ts": <timestamp>,
  "sha256": "<sha256 digest>"
}
```

#### `LOGOUT` Success

```json
{
  "status": "ok",
  "message": "<username> logged out"
}
```

#### Generic Error

```json
{
  "status": "error",
  "message": "<error description>"
}
```

## Starter Materials

Download the project starter package from the course page.

Starter materials:

```text
client_root/
server_root/
mitm_root/
setup_net
enter
```

This page and linked information serve as the primary documentation.

## How to Run the Project

This project is intended to run inside a Linux environment. While it should work
in any modern Linux environment, it has only been tested in the class VM. If you
run it in another VM and encounter problems, switch to the class VM to stay on
time.

Working in the same VM creates a uniform platform for other groups who will
evaluate your design later. Otherwise, you will have to provide environment
documentation as well.

### Step 1: Create the Namespace Environment

From the project root, with the home directory assumed below:

```bash
student@student-vm:~$ chmod u+x setup_net
student@student-vm:~$ sudo ./setup_net
```

This creates three Linux network namespaces:

| Namespace | Description |
| --- | --- |
| `ns_client` | The network where the client runs. |
| `ns_mitm` | The intermediate network through which all traffic between the client and server passes. |
| `ns_server` | The network where the server runs. |

Run this script every time the VM is restarted.

### Step 2: Enter Each Environment

Use the `enter` helper script to open a shell in the client, server, or MITM
machine. For example:

```bash
student@student-vm:~$ chmod u+x enter
student@student-vm:~$ sudo ./enter server
root@server:~# ls
server.py  server_storage  users.json
```

Use three terminals to open one shell for each environment.

### Step 3: Run the Programs

In the server shell:

```bash
root@server:~# python3 server.py
```

In the MITM shell:

```bash
root@mitm:~# python3 mitm.py
```

In the client shell:

```bash
root@client:~# python3 client.py
```

It is advised that you create Python virtual environments and run the programs
from within them. That way you can later supply a `requirements.txt` file for
the packages needed to install your modified versions.

## Threat Model and Requirements

Assume the network is adversarial. Malicious clients or intermediate network
nodes may attempt to observe, alter, replay, inject, suppress, or misuse
protocol messages. They may also attempt to access user files and interfere with
normal service operation.

For the scope of this project, the following requirements (R1-R12) define the
security-related expectations of the system.

| Requirement | Description |
| --- | --- |
| R1 | Only a user entitled to a file should be able to view its contents. |
| R2 | An honest user should be able to carry out file operations on files they are permitted to use. |
| R3 | The system should produce a clear and consistent outcome for each request. |
| R4 | A completed operation should correspond to a current request from an honest user. |
| R5 | A completed operation should reflect an honest user's intended operation. |
| R6 | A client should accept a service response only when that response genuinely corresponds to its request. |
| R7 | A user should not be able to access, alter, or remove files they are not permitted to use. |
| R8 | Information produced or exchanged in one interaction should be usable only within its intended session. |
| R9 | Invalid, unexpected, or malformed input should not cause unsafe behavior. |
| R10 | Ordinary misuse of the protocol should not trivially prevent legitimate use by others within the project environment. |
| R11 | The system should leave enough evidence of important events and failures to support later review and debugging. |
| R12 | Any trust necessary for correct behavior must be explicitly established by the system. |

Much of what you will design and evaluate in this project will be with respect
to these 12 expectations. While you may identify other sensible requirements,
grading will be strictly with respect to the ones stated above.

## Groups and Individual Contributions

Each group will have four members. Adjustments will be done by the instructor to
account for an uneven number of students enrolled in the course. Each group
member is expected to participate in all stages.

Project work in this course is group-based, and the default assumption is that
all group members receive the group's project score. However, substantial
contribution imbalance within a group may lead to individual grade adjustments.

As part of Stage 4 evaluation, each student will complete a confidential
peer-contribution form rating the contributions of the other members of their
group. These ratings are intended to identify serious outliers in contribution,
not to regrade the project independently.

If the feedback indicates a substantial and consistent contribution imbalance,
individual project grades may be adjusted accordingly. This process is intended
to support fair group grading while keeping the project collaborative.

Groups must be formed by April 2, 2026, which is the second day of class, before
class. If you have a group of four, send an email to the instructor with the
group member names. For students who have not joined a group by then, the
instructor will make the group assignment and announce it in class.

It is imperative that group formation is not delayed, since the Stage 1 deadline
is close.

## Project Stages

The project will advance in four stages, each with its own deliverables,
deadlines, and grading. The final score for the project will be a weighted sum
of the scores from each stage.

| Stage | Weight | Goal |
| --- | ---: | --- |
| Stage 1 | 20% | Study the baseline implementation and demonstrate how it fails one or more requirements. |
| Stage 2 | 40% | Propose and implement a revised version to meet failing requirements. |
| Stage 3 | 20% | Perform a security review of another group's design. |
| Stage 4 | 20% | Present a revision plan based on review, as well as project-level reflections. |

Details on each stage are available in the linked pages.

### Deliverables

Each stage has its own deliverables and submission requirements. Depending on
the stage, you may be required to submit design files, code, structured attack
memos, or attack scripts. Consult the individual stage page for exact details.

### Deadlines

| Milestone | Due date |
| --- | --- |
| Stage 1 | April 17, 2026 |
| Stage 2, Part A | May 1, 2026 |
| Stage 2, Part B | May 15, 2026 |
| Stage 3 | May 28, 2026 |
| Stage 4 | June 4, 2026 |

This is not just an exercise in coding skills, but also in the ability to work
in a multi-group environment and communicate findings to other groups.
Specifically, outputs of Stage 2 and Stage 3 are vital for other groups to
proceed. Therefore, meeting the deadlines is critical.

## What Packages Are Allowed

You may use standard cryptographic primitives from common Python libraries, but
the actual implementation of the security guarantees has to be fully in the
application-layer code that you write.

This means that you cannot wrap a network connection in Python's TLS
implementation or adopt a prebuilt secure transport wrapper. Even doing so would
leave many requirements unaddressed. You may draw on ideas from existing
protocols, including TLS, and are encouraged to do so.

If you have doubts about whether a certain package is allowed, ask the
instructor early.

## Keying Material

Secrets are vital components of network protocols based on cryptographic
approaches. However, management of these secrets is a problem in itself. You
cannot assume that secrets are "just" present for use in the system.

For example, users of the service create accounts and use login/passwords to
authenticate. You can store the passwords in a secure form to make trivial
attacks infeasible. However, if you also require a shared secret to be present,
then the establishment and proper management of that secret must be performed by
your protocol. Failure to do so is a violation of requirement R12.

Similarly, Public Key Infrastructure is a critical asset in today's network
security. Each of the client, server, and MITM nodes contain the `/certs` folder
with two certificates. These certificates represent the globally recognized
trusted root CAs within the project.

Each group may request up to two certificates signed by the provided trusted
root CAs at no cost. Send an X.509 CSR file to the instructor to obtain the
certificates, along with a description of who it is for and the purpose for
which it will be used. This allowance applies per group, not per student.

This does not prevent you from creating your own CA for the service, but failure
to incorporate certificate management may violate some requirements.

Any additional certificate request will incur a 3-point deduction per
certificate in the Stage 2 scores, including reissuance caused by CSR mistakes,
incorrect certificate details, or other preventable errors. Plan carefully before
requesting certificates.

Do not take secrets for granted as something you copy-paste from one file to
another. Plan around their management.

## Final Notes

Treat the early stages seriously. The strongest solutions usually come from
groups that understand the system deeply before trying to secure it.

Do not patch blindly. Preserve functionality, justify your security choices, and
validate your defenses against realistic attacks.
