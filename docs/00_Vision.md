# Argus Vision

## What is Argus?

Argus is an autonomous security research platform designed to assist authorized penetration testing and bug bounty engagements.

Unlike traditional scanners, Argus does not simply execute tools. It observes, reasons, plans, executes, verifies, and documents findings while keeping the human operator in control.

Its objective is to reduce repetitive work while increasing the quality and depth of security assessments.

---

# Philosophy

Argus follows one simple principle:

> Observe everything. Assume nothing.

Every conclusion should be supported by evidence.

Every action should have a reason.

Every finding should be reproducible.

---

# Core Principles

## Human in Control

Argus assists the researcher.

The operator always defines scope and approves impactful actions.

---

## Evidence First

Every conclusion must link to evidence.

Examples include:

* HTTP requests
* HTTP responses
* Screenshots
* Browser recordings
* Burp history
* Logs

---

## Reason Before Action

Argus should never execute tools simply because they exist.

Every action should answer:

"Why am I doing this?"

---

## Memory Driven

Argus continuously builds a knowledge graph of the engagement.

It should remember:

* endpoints
* parameters
* technologies
* authentication methods
* attack surface
* previous experiments
* discovered relationships

---

## Modular

Every capability should be replaceable.

Recon, browser automation, Burp integration, reporting, and memory should all function as independent modules.

---

# Long-Term Vision

Argus aims to become a virtual security teammate capable of assisting researchers throughout an entire assessment—from reconnaissance to evidence collection and reporting—while remaining transparent, explainable, and respectful of authorized testing boundaries.
