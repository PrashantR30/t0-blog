---
title: "Playgrounds of the Mind: Changing the Agentic Ops Trust Paradigm"

slug: "playgrounds-of-the-mind"

date: 2026-06-24T00:00:00Z

author: "Randy Bias"

tags: ["agents", "security", "sandbox", "playground", "autonomy"]

categories: ["operations", "aiops"]

draft: false

description: "Why the sandbox 'straightjacket' approach to securing AI ops agents is fundamentally flawed, and what a 'playground' paradigm—autonomy within bounded infrastructure, vetted workflows, oversight, and greylisted boundaries—looks like instead."

image: "/images/playgrounds-of-the-mind/cover.png"
---

<style>
pre, .highlight { overflow-x: auto; }
pre code { display: block; white-space: pre; }
</style>

## Introduction

The fundamental problem with existing approaches to making AI agents "secure"—particularly for the purpose of letting them help with IT operations—is that they rely on what I call the "straightjacket" methodology. You know it better as the **sandbox**.

The sandbox paradigm says: we know what the agent can and cannot do, what it can and cannot access, and we will build a hardened containment in which it is completely restricted. Lock it down. Predict everything in advance.

Unfortunately, this runs counter to what we keep seeing in the wild: unrestricted, free agents (!) are more effective at their jobs. The more you wrap a straightjacket around [OpenClaw](https://github.com/openclaw/openclaw) or [Hermes](https://github.com/nousresearch/hermes-agent), the less useful they become.

So what is the alternative?

The alternative is what I call the **playground**. Rather than trying to predict everything your agent might do and plan for it in advance, you create a safe space—the playground—in which it operates as an unprivileged user, yet with relatively full autonomy. It can install its own software, write to disk, search the web, and so on. Much like a child at a playground—and let's be honest, in the AI era we are effectively managing idiot savants—agents need oversight and rules. In the playground paradigm, agents are free within their running environment to do whatever they need to do for their tasks, but at certain key boundaries, certain rules are enforced. Meanwhile, everything they do is monitored, logged, and an "adult" can step into the room as necessary to take action.

## The Playground Paradigm in Detail

Let's talk about what an agentic playground actually looks like in the context of agentic ops (aka "[AIOps](https://en.wikipedia.org/wiki/AIOps)," although that term is now badly overloaded).

If you were to write this up as a system/agent prompt, it would read something like this:

> You can only operate on production through vetted, deterministic workflows that a human has validated. You can choose any tool you like in the playground to figure out what you need for your task, but you may not use those tools against production. You can create workflows for approval. You cannot log in to production systems or access their APIs directly yourself.

Now, obviously a system prompt isn't the way to *enforce* this. You need real mechanisms underneath. Here's what those look like:

| **Playground Aspect** | **What it Allows** | **What it Doesn't Allow** |
| :-- | :-- | :-- |
| Playground infrastructure | A place for the agent to run autonomously | Root access |
| Pre-vetted workflows | Deterministic production operations that are fully audited | Non-deterministic actions against production |
| Oversight "nanny" agent | Relative autonomy | Bad behavior from running agents—privilege escalation attempts, suspect tool-chain installs, anomalous behavior |
| Boundary enforcement | General web access, restricted access to corporate-approved LLMs, credential injection and/or workflow validation | Unrestricted production access (greylisted); only workflow-based access |

Let's take these one at a time.

**Playground infrastructure** is a container, a VM, or the like, with full non-root access, the ability to install software and tools as needed, and room to run multiple agents as necessary.

**Pre-vetted workflows** can be created through mechanisms such as [Swamp](https://swamp.club), precreated TypeScript DAGs, or a custom mechanism. Swamp's own framing—[deterministic automation for a probabilistic system](https://stack72.dev/deterministic-automation-for-a-probabilistic-system/)—captures exactly why this layer matters. Workflows are created through a [human-in-the-loop](https://en.wikipedia.org/wiki/Human-in-the-loop) (HITL) process, provided in the playground, then signed and made immutable. Each workflow carries a specific digital identity that the boundary enforcement mechanism can validate. All workflow runs are fully auditable and leave append-only entries in immutable logs. Agents can even draft new workflows for humans to approve—that's part of the job.

The **nanny agent** is a security mechanism, possibly at least partly agentic itself, whose only job is oversight of the agents in the playground. The nanny has limited external access and runs in a restrictive sandbox of its own—outside the playground. Its job is to watch for obvious attempts by the playground agents to exceed their authority, and potentially to shut down a rogue agent proactively.

**Boundary enforcement** looks a bit different from the traditional approaches we've taken, so I'm using a new term for it. It's a mix of "allowlisting" and "blocklisting," so I'm calling it a **greylisting** approach. Boundary enforcement for a playground focuses on providing relatively rich access to the internet: most sites are allowed, so that agents can do research, gather data, and so on. How open it is comes down to corporate policy—essentially the same access an employee would have—with a few key exceptions:

- Only approved corporate LLM API endpoints are available, to provide compliance and security guarantees in regulated environments.
- Corporate resources, particularly the ones the playground agents are responsible for exercising, are only accessible through pre-vetted mechanisms (aka "workflows").
- Workflows have credentials injected at the boundary, or present a signing identity to the boundary enforcement mechanism that validates their ability to access those corporate resources. Workflows are immutable and unreadable after being validated and signed.

So how does this all fit together?

## Why This Works

This approach works because it does all of the following:

1. Agents are allowed to "think for themselves" in the playground. They're given a "playground of the mind" for what are essentially idiot savants.
2. Agents have specific roles and specific corporate resources they can act on—but only through human-approved mechanisms, with no direct access to those resources, while still being able to operate on them.
3. The scope of an agent's work and tasks is clear, so that the oversight "nanny" agent has a reasonably clear understanding of what the agent can and cannot do, and what constitutes "bad behavior."

## Playgrounds vs. Sandboxes

I'll go out on a limb here: the sandbox direction is fundamentally flawed. Straightjackets for AI agents will probably never work. The very act of limiting an agent's options limits the agent in ways that make it less useful. LLMs are savants who need to be given free rein with clear oversight, rather than being locked into a straightjacket of precognitive dysfunction.

There is no way to fully allowlist or blocklist an agent doing its work. And what those lists *need* to contain changes over time. A more dynamic, mixed model is required. Giving agents clear boundaries and roles is important. Using all of that to provide intelligent, automated oversight is critical. Being able to clearly and smartly enforce behavior as agents cross the playground boundary is a hard requirement.

Most importantly, cutting agents loose to do (mostly) whatever they want inside the playground lets them be themselves—which leads to better outcomes, provides greater flexibility, and avoids futile attempts to define rigid enforcement structures that simply aren't manageable or maintainable over time.
