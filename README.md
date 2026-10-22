# STRIDE Threat Model Study – E-Commerce Microservices

**Program:** IBM SkillsBuild Cybersecurity Bootcamp  
**Project #11:** STRIDE Threat Model Study – mapping microservice data flows and structural threats using OWASP Threat Dragon

## Overview
This project builds a complete STRIDE threat model for an e-commerce platform made of microservices
(API Gateway, Auth, Order, Payment and Notification services, two databases and an external payment provider).
The model is created in **OWASP Threat Dragon** (saved as JSON) and then analysed by a Python tool,
`stride_analyzer.py`, which turns the raw model into risk metrics, charts and a gap report.

## Features
- Parses an OWASP Threat Dragon v2 JSON model (actors, processes, data stores, data flows, trust boundaries)
- Exports all threats to `threats.csv` (element, STRIDE category, severity, status, mitigation)
- **STRIDE-per-element coverage check** – flags applicable categories nobody analysed
- Risk scoring: inherent score (High=9, Medium=5, Low=2) and residual score (mitigated threats count 20%)
- Charts: STRIDE distribution, status/severity, element-vs-STRIDE risk heatmap
- Renders the Data Flow Diagram with trust boundaries and open-threat counts
- Generates a Markdown summary with the Top 10 open threats

## Project structure
```
.
├── stride_analyzer.py                    # main code
├── requirements.txt
├── README.md
├── Project_Report.docx
├── threat_model/
│   └── ecommerce_threat_model.json       # OWASP Threat Dragon model (open it in Threat Dragon)
└── output/                               # generated results (CSV, PNG charts, summary)
```

## How to run
1. Install Python 3.10+ and clone the repo:
   ```bash
   git clone <your-repo-url>
   cd <repo-folder>
   ```
2. (Optional) create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate        # Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the analyzer:
   ```bash
   python stride_analyzer.py --model threat_model/ecommerce_threat_model.json --out output
   ```
5. Open the `output/` folder for `threats.csv`, `coverage_gaps.csv`, the PNG charts and `analysis_summary.md`.

### Viewing the model in OWASP Threat Dragon
Go to https://www.threatdragon.com (web app) → *Open a Threat Model* → *Open from local file* → select
`threat_model/ecommerce_threat_model.json`. You can edit threats and re-run the analyzer on the re-exported file.

## Results (sample model)
| Metric | Value |
|---|---|
| Elements analysed | 17 |
| Threats identified | 62 |
| Open / Mitigated | 38 / 24 |
| High-severity still open | 20 |
| Coverage gaps found | 3 elements |

## Tools & technologies
Python 3, pandas, matplotlib, OWASP Threat Dragon, STRIDE methodology, VS Code, Git/GitHub.

## Author
Himanshu Rawat – himanshurawat9520@gmail.com
