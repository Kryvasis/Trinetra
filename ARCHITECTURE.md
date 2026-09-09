# Cortex architecture

This diagram shows the runtime components, authoritative data flow, governance
path, integrity boundary, external dependencies, and verification pipeline.

```mermaid
flowchart TB
    Operator["Network operator"]
    Reviewer["Independent rule reviewer"]
    Auditor["Auditor / report verifier"]

    Files["Sanitized configuration files<br/>single or bulk"]
    Targets["Authorized SSH device or<br/>HTTPS configuration source"]

    subgraph Host["Cortex application host — current local trust boundary"]
        direction TB

        subgraph UI["React + Vite workspace"]
            direction LR
            Dashboard["Overview"]
            Upload["Upload & collect"]
            Results["Results & posture diff"]
            Devices["Session devices"]
            Training["Training governance"]
            Assurance["Assurance & verification"]
            System["System health"]
        end

        subgraph Bridge["Flask bridge — validation and orchestration"]
            direction LR
            Boundary["Request boundary<br/>size, identifier and injection validation"]
            API["Session and assessment API"]
            Fetcher["Secure collection adapter<br/>known-hosts, redirect and SSRF controls"]
            Governance["Draft / review / activation API"]
            ReceiptAPI["Receipt issue and verify API"]
            Static["Built SPA and report delivery"]
        end

        subgraph Core["Authoritative assessment engines"]
            direction LR
            Helper["Java bridge helper / CLI"]
            Ingest["Unified ingestion pipeline"]
            Vendor["Vendor resolution and parser registry"]
            Baseline["Vendor-neutral SecurityBaseline"]
            Evaluate["Deterministic control evaluator"]
            Score["Manifest-driven framework scorer"]
            Native["Optional C++ network probes"]
        end

        subgraph Advisory["Advisory intelligence — never authoritative for scoring"]
            direction LR
            ML["TF-IDF + KNN<br/>unknown-syntax suggestions"]
            Narrative["Optional Gemini narrative<br/>number validation + template fallback"]
        end

        subgraph State["Local state — excluded from source control"]
            direction LR
            Sessions[("Session and per-device<br/>assessment evidence")]
            Chain[("Append-linked evidence<br/>hash chain")]
            Audit[("Append-only SQLite<br/>audit events")]
            RuleMap[("Versioned vendor<br/>training map")]
            Key[("Ed25519 assessor key<br/>.cortex/")]
        end

        subgraph Output["Operator and auditor outputs"]
            direction LR
            Finding["Explainable finding<br/>evidence · reason · control · remediation"]
            PDF["Frozen session and<br/>per-device PDF reports"]
            Receipt["Signed integrity receipt<br/>assessment ID · Merkle root · chain tip"]
            Coverage["Coverage and claim-boundary report"]
        end
    end

    Gemini["Optional external Gemini service"]
    Ledger["Independent ledger anchor<br/>NOT CONFIGURED"]

    subgraph Delivery["Repository verification"]
        direction LR
        Actions["GitHub Actions"]
        Tests["Java + Python + C++<br/>frontend lint/build/tests"]
        CodeQL["CodeQL security analysis"]
        SBOM["Dependency inventory<br/>CycloneDX SBOM"]
    end

    Operator --> UI
    Reviewer --> Training
    Auditor --> Assurance
    Files --> Upload
    Targets --> Fetcher

    UI -->|"JSON over /api"| Boundary
    Boundary --> API
    Boundary --> Governance
    Boundary --> ReceiptAPI
    Upload --> API
    Fetcher -->|"configuration text only"| API
    API --> Helper
    Helper --> Ingest
    Native --> Helper
    Ingest --> Vendor
    Vendor --> Baseline
    Baseline --> Evaluate
    Evaluate --> Score

    Ingest -->|"unknown lines"| ML
    ML -->|"suggestion + confidence"| Training
    Training -->|"propose draft"| Governance
    Reviewer -->|"different identity required"| Governance
    Governance -->|"approved rules only"| RuleMap
    RuleMap --> Vendor

    Ingest --> Sessions
    Evaluate --> Sessions
    Sessions --> Chain
    Helper --> Audit
    Score --> Finding
    Sessions --> Finding
    Finding --> Results
    Score --> Narrative
    Narrative -.->|"optional request"| Gemini
    Narrative --> PDF
    Finding --> PDF
    Static --> UI

    Chain -->|"verify before signing"| ReceiptAPI
    Key -->|"local signature"| ReceiptAPI
    ReceiptAPI --> Receipt
    Receipt --> Assurance
    Vendor --> Coverage
    RuleMap --> Coverage
    Coverage --> Assurance
    Receipt -.->|"future adapter only"| Ledger

    Actions --> Tests
    Actions --> CodeQL
    Actions --> SBOM
```

## How to read it

- Solid arrows are implemented runtime paths.
- Dotted arrows cross an optional or currently unimplemented external boundary.
- The Java ingestion, evidence and scoring path is authoritative.
- ML and Gemini outputs are advisory and cannot directly create compliance scores.
- A proposed recognition rule is inert until a different reviewer activates it.
- The signed receipt proves integrity inside the local assessor boundary. The
  independent ledger shown at the edge is deliberately marked as not configured.

## Primary assessment sequence

1. The operator submits a file or authorizes a collection target.
2. Flask validates the request; the secure fetcher returns configuration text only.
3. Java resolves the vendor, builds the normalized baseline and evaluates controls.
4. Evidence is appended to the session chain and the deterministic scorer maps it
   to selected frameworks.
5. Cortex presents explainable findings and generates reports from stored evidence.
6. After chain verification, the assurance service signs a Merkle commitment with
   the local Ed25519 assessor key.
7. An auditor can verify the receipt signature and compare it with currently
   available session evidence.
