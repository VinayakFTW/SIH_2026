# Rogue Kernel

Rogue Kernel is a network threat intelligence system for analyzing inference results, identifying anomalous flows, mapping activity to MITRE ATT&CK, and generating analyst-focused summaries.

## Overview

The project has two parts:

- **React client**: JSON-driven SOC dashboard with charts, severity filtering, alert review, and flow-level reasoning.
- **FastAPI backend**: PCAP inference, health checks, MITRE lookups, and secure Groq summary generation.

The browser never receives the Groq API key. LLM requests are handled by the backend.

## Features

- Load `sample_inference_results.json` or another inference-results JSON file.
- View anomaly rates, scores, severity, tactics, techniques, and traffic metrics.
- Filter and search flow evidence.
- Inspect analyst reasoning for each flow.
- Generate executive summaries with Groq using `openai/gpt-oss-20b`.
- Upload PCAP files through the FastAPI inference endpoint to produce JSON results.
- Map detected activity to MITRE ATT&CK techniques.

## Architecture

```text
PCAP -> FastAPI inference -> JSON results -> React dashboard
                                      |
                                      -> FastAPI Groq summary -> Groq API
```

The current inference controller uses packet-flow aggregation and rule-based anomaly checks. The deep learning model files are reserved for future model integration.

## Requirements

- Python 3.8+
- Node.js 18+
- Wireshark/TShark, required for PCAP parsing
- A Groq API key for generated summaries

## Setup

### Backend

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export GROQ_API_KEY="your-groq-api-key"
python main.py
```

The API runs at `http://localhost:8000`.

### Client

```bash
cd client
npm install
npm run dev
```

The dashboard runs at `http://localhost:5173`.

For a production build:

```bash
npm run build
npm run preview
```

To use a backend on another host or port:

```bash
VITE_API_URL=http://localhost:8000 npm run dev
```

## Dashboard Workflow

1. Open the client at `http://localhost:5173`.
2. Select **Load JSON** and choose an inference-results file.
3. Review the executive anomaly summary and interactive charts.
4. Use **Alert queue** to focus on flows above the anomaly threshold.
5. Expand a flow to inspect its evidence and reasoning.
6. Select **Generate Groq summary** for an LLM-generated report.

The included `sample_inference_results.json` can be used without running the backend.

## JSON Format

The client expects an object containing a `results` array:

```json
{
  "processed_flows": 5,
  "results": [
    {
      "flow_id": "flow-001",
      "metrics": {
        "duration": 0.18,
        "total_fwd_packets": 48,
        "total_bwd_packets": 2,
        "total_length": 3360,
        "packets_per_second": 278,
        "mean_iat": 0.00065
      },
      "threat_assessment": {
        "anomaly_score": 0.92,
        "severity": "Critical",
        "tactic": "Reconnaissance",
        "technique_id": "T1046",
        "technique_name": "Network Service Scanning"
      }
    }
  ]
}
```

## API

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/health` | Check backend status |
| `POST` | `/api/v1/forecast/pcap` | Analyze a `.pcap` or `.pcapng` file |
| `GET` | `/api/v1/intel/mitre/{attack_type}` | Retrieve MITRE enrichment |
| `POST` | `/api/v1/summarize` | Generate a Groq executive summary |

Example summary request:

```bash
curl -X POST http://localhost:8000/api/v1/summarize \
  -H "Content-Type: application/json" \
  -d @threat_data.json
```

## Project Structure

```text
.
├── client/                    React/Vite dashboard
├── controllers/core/          FastAPI endpoint handlers
├── models/                    Threat mapping and model modules
├── pipeline/                  PCAP parsing and flow aggregation
├── training/                  Dataset loading and training utilities
├── llm_summarizer.py          Groq/OpenAI/Ollama/Mock backends
├── main.py                    FastAPI application
├── requirements.txt           Python dependencies
└── sample_inference_results.json
```

## Configuration

Keep local secrets out of version control. Set the Groq key in the shell or a local environment file:

```bash
export GROQ_API_KEY="your-groq-api-key"
```

`config.env` is ignored by Git. Never place API keys in the React client.

## Development Checks

```bash
python -m py_compile main.py llm_summarizer.py
cd client
npm run lint
npm run build
```

## License

See [LICENSE.md](LICENSE.md).
