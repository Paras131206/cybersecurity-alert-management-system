# Cybersecurity Alert Management System

A Java program that manages security alerts using three data structures:

| Data structure | Used for |
|---|---|
| **Queue** (`LinkedList`) | New alerts wait here in arrival order |
| **Priority queue** (`PriorityQueue`) | Gives analysts the most severe alert first; equal severity -> oldest first |
| **Binary search tree** (`AlertBST`, AVL-balanced) | Stores every alert by id for fast search and id-range lookups |

Alert life: `QUEUED -> TRIAGED -> ASSIGNED -> RESOLVED`. Severity can be raised (`escalate`) until an analyst picks the alert up.

## Run

Needs Java 11 or newer.

```bash
java AlertSystem.java
```

It prints a short demo, then runs 22 test cases and ends with `22 passed, 0 failed`.

In VS Code: install the Extension Pack for Java, open `AlertSystem.java` and click **Run** above `main`.

## Files

- `AlertSystem.java`: the whole program, demo and tests in one file
- `how-it-works.html`: an illustrated explanation of the code (open in a browser)
