---
title: "k0rdent and Archestra: An Open-Source Architecture for Agentic Workloads on Multi-Cluster Kubernetes"

date: 2026-05-07T00:00:00Z
author: "Prashant Ramhit"
# slug:
slug: "k0rdent-archestra"
# SEO and Social Media
keywords:
  - kubernetes
  - k0rdent
  - Archestra
  - MCP
  - AI agents
  - agentic AI
  - CNCF
tags:
  - kubernetes
  - k0rdent
  - Archestra
  - MCP
  - AI agents
  - agentic AI
  - CNCF
  - Helm
  - Platform
  - GPU
  - HPC
categories:
  - engineering
  - architecture
  - platform

# Set to false when ready to publish
draft: false

description: "A practical architect view on running agentic operations safely with two complementary open-source control planes built on CNCF standards: k0rdent for clusters, Archestra for agents."
image: "images/2026/05-07-k0rdent-archestra/hero.png"
---
*Two CNCF-aligned, open-source control planes — one for clusters, one for agents — built on Helm, CAPI, OCI, and the Model Context Protocol. A practical architect view on how they fit together.*
---
After more than a decade of operating Kubernetes at scale, the community has converged on a clear lesson: the question is rarely whether to run Kubernetes. The question is what sits above it. A thousand snowflake clusters with a thousand bespoke configurations is what happens when there is no control plane above the clusters themselves. The platform engineering movement of the last several years exists for exactly that reason, and the CNCF ecosystem has produced most of the building blocks we now use to address it is Cluster API, Helm, OpenTelemetry, Prometheus, GitOps tooling, and increasingly, the projects that compose them into operable platforms.

[k0rdent](https://k0rdent.io/) is one of those projects. It is an open-source, Kubernetes-native super control plane, built on Cluster API (CAPI) and developed in the open under the Apache 2.0 license. A single management cluster can orchestrate the lifecycle of many child clusters across AWS, Azure, GCP, vSphere, OpenStack, and bare metal. The [k0rdent documentation](https://docs.k0rdent.io/) covers the architecture in detail.

Three components handle three concerns:

- **KCM** (Cluster Manager) drives cluster lifecycle through declarative `ClusterTemplate` objects.
- **KSM** (State Manager) drives the services running on those clusters through `ServiceTemplate` objects, leveraging Project Sveltos under the hood.
- **KOF** (Observability and FinOps) gives operators telemetry and cost attribution across the fleet.

Templates, GitOps, drift reconciliation, and multi-tenancy by design and the pattern is recognizable, well-tested, and built almost entirely from upstream CNCF projects.

That picture, for traditional and AI workloads alike, was largely complete. The callers reaching the API servers were humans with kubeconfigs and CI pipelines with service accounts. Both could be reasoned about with existing primitives.

A new caller has now arrived.

## A new kind of caller

The [Model Context Protocol](https://modelcontextprotocol.io/) is an open specification that has, in roughly eighteen months, become the default way language models invoke real systems. The protocol is open, the specification is public, and the implementations are largely open-source. The [Archestra MCP catalog](https://archestra.ai/mcp-catalog), itself open-source and community-curated has now indexes more than 850 servers, of which a substantial fraction are official, published by the vendors of the systems they connect to. One of the highest-quality entries in the catalog is the Kubernetes MCP server, which exposes twenty-three tools, including `kubectl_apply`, `kubectl_delete`, `helm_install`, `helm_uninstall`, and `node_management`, cordon and drain. With those tools wired up, an AI agent does everything an SRE does in a kubectl session.

This is not hypothetical anymore. SRE agents triaging CrashLoopBackOff alerts, deployment agents rolling services across regions, and remediation agents responding to KOF cost anomalies are running against managed Kubernetes fleets in production today. They are useful precisely because the action surface is rich. They are operationally risky for the same reason.

The risk is not malice. It is structural. An agent calling `kubectl_apply` against a managed cluster needs the same identity, scope, audit, and policy controls that a human SRE call would need, and most off-the-shelf MCP deployments share a familiar set of gaps:

- The MCP server runs with a static kubeconfig.
- Every call looks like the same actor in the audit log.
- There is no per-agent quota and no per-call audit.
- There is no isolation between agent identities.
- There is no structural defense against prompt injection in tool output.

The blast radius platform teams engineered into their cluster control plane is being silently bypassed at a new boundary above it.

That gap is what [Archestra](https://archestra.ai/) addresses.

![Architecture](../images/2026/05-07-k0rdent-archestra/archestra-on-k0rdent.webp)

## Archestra, layered onto k0rdent

Archestra is an open-source MCP control plane, also Apache 2.0-licensed, with its source available at [github.com/archestra-ai/archestra](https://github.com/archestra-ai/archestra). It sits in the path of every agent call and applies six checkpoints before the call reaches a downstream system:

1. **Registry**: approved MCP servers with versioning and rollback.
2. **Identity**: scoped per agent, OAuth- and SSO-integrated.
3. **Vault**: credentials in HashiCorp Vault or Kubernetes Secrets, injected server-side and never seen by the model.
4. **Dual LLM guardrail**: isolates dangerous tool output from the main agent loop as a structural defense against prompt injection.
5. **Policy**: per-team and per-agent, including spend caps and rate limits.
6. **Audit**: per-call, with metrics exported to Prometheus, traces to OpenTelemetry, and dashboards in Grafana with all standard CNCF observability primitives.

The [Archestra documentation](https://archestra.ai/docs) walks through each of these in detail.

Importantly, Archestra is itself a Kubernetes workload. The platform ships as an OCI Helm chart, deployed the same way most CNCF-aligned platforms are deployed. From a management cluster, the canonical install is:

```bash
helm upgrade archestra-platform \
  oci://europe-west1-docker.pkg.dev/friendly-path-465518-r6/archestra-public/helm-charts/archestra-platform \
  --install \
  --namespace archestra \
  --create-namespace \
  --set postgresql.external_database_url=postgresql://user:password@host:5432/archestra \
  --wait
```

That command is not run by hand on every cluster. The chart can be wrapped as a k0rdent `ServiceTemplate`, committed to a platform Git repository, and rolled across the management estate by KSM:

A `ClusterDeployment` then references the template and supplies environment-specific values, including the database URL resolved from Vault at deploy time. KSM detects drift and reverts unauthorized changes. KCM keeps the cluster underneath on its declared template. KOF observes Archestra's resource consumption alongside everything else in the fleet. The rollout is GitOps-friendly because the `ServiceTemplate` is itself a versioned YAML object. Upgrading Archestra across the estate becomes one bumped version field, the standard CNCF-pattern declarative-rollout story.

The install relationship matters because it determines who owns what. k0rdent is the foundation; Archestra is the agent-boundary control plane that layers onto it. At runtime, agent calls flow the other direction, they hit Archestra first, and only then reach the cluster k0rdent governs — but the install order and the call order are different stories about the same architecture, and being explicit about which is which avoids confusion.

## The full picture: industries, control planes, workloads

![workloads](../images/2026/05-07-k0rdent-archestra/workload.webp)



The diagram above shows what the architecture looks like once both control planes are in place across regulated environments. It reads top to bottom in three movements.

At the top sit the industries the platform serves. Healthcare, where agents read and write FHIR records and access controls have to satisfy HIPAA and GDPR. Banking and finance, where treasury and risk agents handle payment flows under PCI, SOX, and DORA. Government, where sovereign-AI deployments live behind FedRAMP and NIS2. Energy and utilities, where edge ops agents act on field equipment governed by NERC CIP and IEC 62443. Telco and critical infrastructure, where network operations agents touch 5G core systems under 3GPP, ETSI, and ENISA. Each industry brings its own compliance frame, but the operational primitives required are scoped identity, vaulted credentials, per-call audit, drift reconciliation, cost attribution, are the same across all five, and all of them are addressable with open-source primitives.

In the middle sit the two control planes. Archestra is the agent boundary at Layer 1 because it is the first gate every agent call passes. The six checkpoints are: registry, identity, vault, dual-LLM guardrail, policy, audit which convert an unstructured tool invocation into a governed, identifiable, budgeted action. Underneath sits k0rdent, the cluster boundary at Layer 2, labeled second not because it is secondary but because it is the foundation. KCM, KSM, and KOF cover cluster lifecycle, service lifecycle, and observability. The annotation between the two layers is the install relationship: Archestra deployed onto k0rdent as a `ServiceTemplate`, KSM rolling it across the estate.

At the bottom sit the workload categories the architecture serves. This is where the complementarity story becomes concrete.

**Traditional workloads.** Web apps, APIs, databases, microservices, batch jobs running on EKS, AKS, GKE, or vSphere. Archestra contributes scoped agent identity per service and vaulted credentials, so an agent integrating Postgres or Redis never holds the connection string in its context. k0rdent contributes declarative cluster lifecycle, drift reversion, and unified cost attribution per team. Traditional workloads gain agentic operations without giving up the operational maturity the platform team has spent years building.

**AI and GPU workloads.** Inference, training, fine-tuning, agentic platforms, running on NVIDIA H100 fleets, MIG-partitioned GPUs, Run:ai schedulers, and partner clouds. Archestra contributes per-agent budget caps that prevent runaway inference loops from consuming a quarter's GPU budget in an afternoon, and the prompt-injection guard on tool I/O matters more here than anywhere else because the agents have the highest action surface. k0rdent contributes GPU virtualization with hard tenant isolation, the ability to ship model serving as a `ServiceTemplate` so a new tenant gets a vetted inference stack on demand, and GPU FinOps tracking that goes down to token-to-watt costing through KOF. AI workloads benefit most visibly from the install reality: when a new model-serving template is promoted, KSM rolls it across the estate, and Archestra's per-agent budgets travel with the workload.

**HPC workloads.** Simulation, genomics, risk modeling, scientific workflows, often running on Slurm, MPI, bare-metal clusters with InfiniBand fabrics. The community is increasingly seeing agents triggering HPC jobs, a researcher's agent submitting a genomics pipeline, a quant's agent kicking off a Monte Carlo run. Archestra contributes scoped job-submission identity so the audit trail attributes the run to the agent and the human behind it, which matters intensely when the run is regulated. k0rdent contributes bare-metal and HPC scheduler integration, multi-tenant fabric and storage policy, and node-hour cost attribution. The same control-plane primitives that work for a containerized API also work for a bare-metal MPI job because both are governed by the same identity, policy, and audit fabric.

The legend on the diagram is the simple version of all of this: yellow squares are what Archestra contributes, blue squares are what k0rdent contributes. Read down a workload column and the color mix tells you which control plane is doing what work.

## A worked example

The clearest demonstration is the simplest one. An SRE agent on call for the `payments` namespace receives an alert: `payments-api` is in CrashLoopBackOff. The agent is wired to the Kubernetes MCP and is supposed to triage and remediate.

Without Archestra in front, the MCP uses a static kubeconfig that the platform team installed when the agent was deployed. The agent reads pod logs, which contain attacker-controllable text from a poisoned upstream image. It decides the fix is "delete the deployment and reapply the manifest" and executes. The audit log records a generic service account doing both actions. There is no budget, no scope, no signature on the call. If the manifest the agent generates is wrong, or if the log content prompted it to do something else entirely, only the cluster's own RBAC stands between the agent and a production incident.

With both control planes in path, the same alert plays out as a controlled sequence:

1. **Authenticate.** Archestra authenticates the agent against its scoped identity: `sre-agent-payments`, namespace-bound and pulls the kubeconfig from the vault.
2. **Budget.** The session-level policy caps the call at five mutating actions before a human is consulted.
3. **Sanitize input.** Pod logs flow through Dual LLM, which extracts the structural facts the agent needs (error type, affected pods, recent deploys) without exposing raw injectable text to the main loop.
4. **Decide and log.** The agent decides on a fix; Archestra logs the call with a signed audit record.
5. **Cluster-side enforcement.** k0rdent's RBAC confirms the scoped identity can write only to the `payments` namespace, and the `ServiceTemplate` policy validates the manifest against an approved golden path.
6. **Drift correction.** If the agent tries to drift outside that envelope, apply something out of policy, target a different namespace, install a Helm chart not in the catalog, k0rdent's reconciliation reverts it. KOF records the cost.

Same agent. Same alert. Same MCP. The operational posture is not in the same neighborhood.

## Two open-source projects, one platform investment

Both projects are open source and built on standards the CNCF community has spent years standardizing. k0rdent is a CNCF project, with its source under [github.com/k0rdent/k0rdent](https://github.com/k0rdent/k0rdent), built on Cluster API and integrating Project Sveltos, Flux, and the broader Kubernetes-native toolchain. Archestra has joined the CNCF and the Linux Foundation, with its source under [github.com/archestra-ai/archestra](https://github.com/archestra-ai/archestra), and is built on Helm, OCI, OpenTelemetry, and the Model Context Protocol open spec. Neither asks an organization to adopt a proprietary control plane or rewrite its platform. Both slot into GitOps and Helm-based workflows the community already runs.

Most teams adopting agents today did not have time to plan a strategy first. Their developers shipped the integrations, and now the platform team is asked to govern the result. The right response is not to slow that adoption down. It is to layer the missing control plane onto the foundation the platform team has already built by using open primitives, at the boundaries where governance actually belongs and let the agentic layer inherit the operational maturity of everything underneath it.

The architecture described here is one pattern, not the only pattern. Other communities will compose these primitives differently, and that is healthy. The two control planes are independent open-source projects with overlapping audiences and complementary scope. They are useful together because the cluster boundary alone is not enough once agents arrive, and because an agent gateway alone is not enough without a governed substrate to land on. Archestra without k0rdent below it routes risk faster. k0rdent without Archestra in front of it just hopes the agents calling it are well-behaved. Together, every agent action is governed by two control planes designed for two different boundaries.

## Get involved

Both projects are community-driven and welcome contributions:

- **k0rdent**: code at [github.com/k0rdent/k0rdent](https://github.com/k0rdent/k0rdent), docs at [docs.k0rdent.io](https://docs.k0rdent.io/), monthly community calls (third Thursday, 4 PM UTC), and the `#k0rdent` channel on the [CNCF Slack](https://slack.cncf.io/).
- **Archestra**: code at [github.com/archestra-ai/archestra](https://github.com/archestra-ai/archestra), docs at [archestra.ai/docs](https://archestra.ai/docs), MCP catalog at [archestra.ai/mcp-catalog](https://archestra.ai/mcp-catalog), and a community Slack at [archestra.ai/join-slack](https://archestra.ai/join-slack).

Issues, PRs, RFCs, and use-case write-ups are all welcome — the architecture pattern matures faster when more practitioners poke holes in it.

---

**A webinar walking through this architecture in practice is coming soon — watch this space.**