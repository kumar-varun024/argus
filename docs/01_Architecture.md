# Argus Architecture

The following diagram maps the core architecture of the Argus conversational AI and research orchestration system as stabilized in Sprint 13.

```mermaid
graph TD
    classDef ui fill:#1E293B,stroke:#64748B,stroke-width:2px,color:#F8FAFC
    classDef context fill:#0F172A,stroke:#3B82F6,stroke-width:2px,color:#F8FAFC
    classDef core fill:#020617,stroke:#10B981,stroke-width:2px,color:#F8FAFC
    classDef engine fill:#171717,stroke:#F59E0B,stroke-width:2px,color:#F8FAFC
    classDef data fill:#000000,stroke:#8B5CF6,stroke-width:2px,color:#F8FAFC

    A[Conversation Workspace]:::ui
    B[Research Context Engine]:::context
    C[Mission]:::core
    D[Investigation]:::core
    E[Research Planner]:::engine
    F[Workflow Orchestrator]:::engine
    G[Evidence System]:::data
    H[Knowledge Graph]:::data

    A -->|Contextualizes| B
    B -->|Scopes & Bounds| C
    C -->|Spawns| D
    D -->|Informs| E
    E -->|Schedules| F
    F -->|Collects| G
    G -->|Extracts entities| H
    H -.->|Retrieval| B
```

## Core Components
- **Conversation Workspace**: The user interface for interacting with Argus. Handles persistent messaging and multimodal evidence integration.
- **Research Context Engine**: Bridges conversations and missions by synthesizing conversation context, active scopes, and historical graph data.
- **Mission**: The central entity representing a scoped research effort, bounding all activity by authorization policies and target constraints.
- **Investigation**: Tracked hypotheses and objectives within a specific mission.
- **Research Planner**: Intelligence component that decides what steps to take to resolve investigations based on the current context.
- **Workflow Orchestrator**: Executes scheduled workflows and agent tasks based on the research plan, capturing stdout/stderr and raw artifacts.
- **Evidence System**: Manages multimodal artifacts, screenshots, and logs, preserving lineage from orchestrator workflows.
- **Knowledge Graph**: The unified intelligence layer mapping targets, workflows, business objects, endpoints, and relationships.
