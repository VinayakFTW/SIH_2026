"""
LLM-based Threat Summarizer
Generates narrative threat descriptions and executive summaries
Supports OpenAI, Ollama (local), and mock backends
"""

import os
from typing import Dict, Any, Optional
from abc import ABC, abstractmethod
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LLMBackend(ABC):
    """Abstract base class for LLM backends"""
    
    @abstractmethod
    def generate(self, prompt: str) -> str:
        """Generate text from prompt"""
        pass


class OpenAIBackend(LLMBackend):
    """OpenAI API backend using GPT models"""
    
    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-3.5-turbo"):
        """
        Initialize OpenAI backend
        
        Args:
            api_key: OpenAI API key (uses OPENAI_API_KEY env var if not provided)
            model: Model name (gpt-4 or gpt-3.5-turbo)
        """
        try:
            import openai
        except ImportError:
            raise ImportError("openai package not found. Install with: pip install openai")
        
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError(
                "OpenAI API key not provided and OPENAI_API_KEY not set. "
                "Get a key from https://platform.openai.com/api-keys"
            )
        
        self.client = openai.OpenAI(api_key=self.api_key)
        self.model = model
        logger.info(f"Initialized OpenAI backend with model: {model}")
    
    def generate(self, prompt: str) -> str:
        """Generate text using OpenAI API"""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity threat analysis expert."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=1000
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"OpenAI API error: {str(e)}")
            raise


class GroqBackend(OpenAIBackend):
    """Groq API backend using Groq's OpenAI-compatible API."""

    def __init__(self, api_key: Optional[str] = None, model: str = "openai/gpt-oss-20b"):
        self.api_key = api_key or os.getenv("GROQ_API_KEY")
        if not self.api_key:
            raise ValueError(
                "Groq API key not provided and GROQ_API_KEY not set. "
                "Get a free key from https://console.groq.com/keys"
            )

        try:
            import openai
        except ImportError:
            raise ImportError("openai package not found. Install with: pip install openai")

        self.client = openai.OpenAI(
            api_key=self.api_key,
            base_url="https://api.groq.com/openai/v1",
        )
        self.model = model
        logger.info(f"Initialized Groq backend with model: {model}")


class OllamaBackend(LLMBackend):
    """Local Ollama backend for open-source LLMs"""
    
    def __init__(self, model: str = "llama2", base_url: str = "http://localhost:11434"):
        """
        Initialize Ollama backend
        
        Args:
            model: Model name (llama2, neural-chat, mistral, etc.)
            base_url: Ollama server URL
        """
        try:
            import requests
        except ImportError:
            raise ImportError("requests package not found. Install with: pip install requests")
        
        self.base_url = base_url
        self.model = model
        
        # Test connection
        try:
            response = requests.get(f"{base_url}/api/tags", timeout=5)
            response.raise_for_status()
            logger.info(f"Connected to Ollama at {base_url}")
        except Exception as e:
            raise ConnectionError(
                f"Could not connect to Ollama at {base_url}. "
                f"Make sure Ollama is running: `ollama serve`"
            ) from e
        
        self.requests = requests
        logger.info(f"Initialized Ollama backend with model: {model}")
    
    def generate(self, prompt: str) -> str:
        """Generate text using Ollama API"""
        try:
            response = self.requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "temperature": 0.7,
                },
                timeout=60
            )
            response.raise_for_status()
            return response.json().get("response", "").strip()
        except Exception as e:
            logger.error(f"Ollama API error: {str(e)}")
            raise


class MockBackend(LLMBackend):
    """Mock backend for testing without external API"""
    
    def __init__(self):
        logger.info("Initialized Mock backend (for testing)")
    
    def generate(self, prompt: str) -> str:
        """Generate mock response"""
        # Parse threat data from prompt to generate contextual mock response
        
        if "anomaly_rate" in prompt and "0.45" in prompt:
            return (
                "🚨 **CRITICAL THREAT ASSESSMENT**\n\n"
                "Our analysis detected a **45% anomaly rate** in your network traffic, "
                "indicating a significant security incident in progress. "
                "Multiple flows exhibit behavioral patterns consistent with:\n\n"
                "• **T1046 - Network Service Discovery**: Reconnaissance probing detected\n"
                "• **T1498 - Network Denial of Service**: Volumetric spike indicators present\n"
                "• **T1110 - Brute Force**: High-rate connection attempts observed\n\n"
                "**Immediate Actions Recommended:**\n"
                "1. Enable Enhanced Flow Monitoring\n"
                "2. Block Suspicious Source IPs\n"
                "3. Escalate to Security Operations Center\n"
                "4. Preserve PCAP for forensic analysis\n\n"
                "**Forecasting Horizon:** 30 seconds. Expect continued attack activity."
            )
        elif "anomaly_rate" in prompt:
            return (
                "✅ **Network Status: Nominal**\n\n"
                "Analysis indicates healthy network behavior with minimal anomalies. "
                "The detected flows show characteristics consistent with normal business operations:\n\n"
                "• Balanced packet rates\n"
                "• Expected protocol distributions\n"
                "• Standard session durations\n\n"
                "**Recommendations:**\n"
                "Continue baseline monitoring. No immediate action required."
            )
        else:
            return (
                "🔍 **Threat Analysis Summary**\n\n"
                "System performing threat analysis on network flows. "
                "Review detailed metrics in dashboard for comprehensive assessment."
            )


class ThreatSummarizer:
    """
    Main interface for threat summarization
    Generates narrative threat descriptions using LLM
    """
    
    # System prompt for threat analysis
    SYSTEM_PROMPT = """You are an expert cybersecurity threat analyst with deep knowledge of:
- Network traffic patterns and anomalies
- MITRE ATT&CK framework and threat tactics
- Intrusion detection and network security
- Threat hunting and forensic analysis

Your task is to analyze threat data and provide:
1. Executive summary of detected threats
2. Severity assessment and impact analysis
3. Relevant MITRE ATT&CK tactics and techniques
4. Recommended immediate actions
5. Forecasting insights for proactive defense

Keep responses concise, actionable, and focused on cybersecurity implications.
Use clear formatting with bullet points and headings."""

    def __init__(self):
        """Initialize summarizer (backends are lazy-loaded)"""
        self.backend = None
        logger.info("ThreatSummarizer initialized")
    
    def _initialize_backend(
        self,
        provider: str,
        model_name: str,
        api_key: Optional[str] = None
    ) -> LLMBackend:
        """Initialize and cache LLM backend"""
        
        if provider == "OpenAI":
            return OpenAIBackend(api_key=api_key, model=model_name)
        elif provider == "Groq":
            return GroqBackend(api_key=api_key, model=model_name)
        elif provider == "Local (Ollama)":
            return OllamaBackend(model=model_name)
        elif provider == "Mock (Testing)":
            return MockBackend()
        else:
            raise ValueError(f"Unknown provider: {provider}")
    
    def _build_threat_prompt(self, threat_data: Dict[str, Any]) -> str:
        """Build detailed prompt from threat data"""
        
        top_tactics = threat_data.get("top_tactics", {})
        top_techniques = threat_data.get("top_techniques", {})
        severity_dist = threat_data.get("severity_distribution", {})
        
        # Format tactics list
        tactics_str = "\n".join(
            f"  - {tactic}: {count} flows"
            for tactic, count in list(top_tactics.items())[:5]
        ) if top_tactics else "  - None detected"
        
        # Format techniques list
        techniques_str = "\n".join(
            f"  - {tech}: {count} flows"
            for tech, count in list(top_techniques.items())[:5]
        ) if top_techniques else "  - None detected"
        
        # Format severity distribution
        severity_str = "\n".join(
            f"  - {sev}: {count} flows"
            for sev, count in severity_dist.items()
        ) if severity_dist else "  - Unknown"
        
        prompt = f"""{self.SYSTEM_PROMPT}

THREAT DATA ANALYSIS:
=====================

Network Statistics:
  - Total Flows Analyzed: {threat_data.get('total_flows', 0)}
  - Anomalies Detected: {threat_data.get('anomalies_detected', 0)}
  - Benign Flows: {threat_data.get('benign_flows', 0)}
  - Anomaly Rate: {threat_data.get('anomaly_rate', 0)*100:.2f}%
  - Maximum Anomaly Score: {threat_data.get('max_anomaly_score', 0):.4f}
  - Average Anomaly Score: {threat_data.get('avg_anomaly_score', 0):.4f}

Top Detected MITRE ATT&CK Tactics (in anomalous flows):
{tactics_str}

Top Detected MITRE ATT&CK Techniques (in anomalous flows):
{techniques_str}

Threat Severity Distribution:
{severity_str}

Based on this threat data, provide a comprehensive executive summary that includes:
1. Overall threat assessment (Critical/High/Medium/Low)
2. Key findings about the detected anomalies
3. Most likely attack vectors based on detected tactics
4. Immediate action items
5. Forecasting insights (what to watch for next)

Format with clear headings and bullet points."""
        
        return prompt
    
    def generate_summary(
        self,
        threat_data: Dict[str, Any],
        provider: str = "Mock (Testing)",
        model_name: str = "gpt-3.5-turbo",
        api_key: Optional[str] = None,
    ) -> str:
        """
        Generate threat summary from threat data
        
        Args:
            threat_data: Dictionary with threat statistics and metrics
            provider: LLM provider ("Groq", "OpenAI", "Local (Ollama)", "Mock (Testing)")
            model_name: Model name for the provider
            api_key: API key (for Groq or OpenAI)
        
        Returns:
            Generated threat summary text
        """
        try:
            # Initialize backend
            backend = self._initialize_backend(provider, model_name, api_key)
            
            # Build prompt
            prompt = self._build_threat_prompt(threat_data)
            
            # Generate summary
            logger.info(f"Generating summary with {provider} ({model_name})")
            summary = backend.generate(prompt)
            
            return summary
        
        except Exception as e:
            logger.error(f"Error generating summary: {str(e)}")
            raise
    
    def generate_flow_summary(
        self,
        flow_id: str,
        metrics: Dict[str, Any],
        threat_assessment: Dict[str, Any],
        provider: str = "Mock (Testing)",
        model_name: str = "gpt-3.5-turbo",
        api_key: Optional[str] = None,
    ) -> str:
        """
        Generate summary for a specific anomalous flow
        
        Args:
            flow_id: Identifier for the flow
            metrics: Flow metrics dictionary
            threat_assessment: MITRE mapping and threat info
            provider: LLM provider
            model_name: Model name
            api_key: API key for OpenAI
        
        Returns:
            Flow-specific summary
        """
        try:
            backend = self._initialize_backend(provider, model_name, api_key)
            
            prompt = f"""{self.SYSTEM_PROMPT}

ANOMALOUS FLOW ANALYSIS:
========================

Flow ID: {flow_id}

Metrics:
  - Duration: {metrics.get('duration', 0):.3f}s
  - Total Forward Packets: {metrics.get('total_fwd_packets', 0)}
  - Total Backward Packets: {metrics.get('total_bwd_packets', 0)}
  - Total Bytes: {metrics.get('total_length', 0):,}
  - Packets Per Second: {metrics.get('packets_per_second', 0):.2f}
  - Mean Packet Length: {metrics.get('mean_packet_length', 0):.1f} bytes
  - Mean IAT (ms): {metrics.get('mean_iat', 0)*1000:.3f}
  - Bytes Per Second: {metrics.get('bytes_per_second', 0):.1f}

Threat Assessment:
  - Tactic: {threat_assessment.get('tactic', 'Unknown')}
  - Technique ID: {threat_assessment.get('technique_id', 'N/A')}
  - Technique Name: {threat_assessment.get('technique_name', 'Unknown')}
  - Severity: {threat_assessment.get('severity', 'Unknown')}
  - Anomaly Score: {threat_assessment.get('anomaly_score', 0):.4f}

Provide a concise (2-3 sentences) threat description explaining:
1. Why this flow was flagged as anomalous
2. What attack technique this aligns with
3. Recommended immediate action"""
            
            logger.info(f"Generating flow summary for {flow_id}")
            summary = backend.generate(prompt)
            
            return summary
        
        except Exception as e:
            logger.error(f"Error generating flow summary: {str(e)}")
            raise


# Example usage
if __name__ == "__main__":
    # Test mock backend
    summarizer = ThreatSummarizer()
    
    test_data = {
        'total_flows': 150,
        'anomalies_detected': 68,
        'benign_flows': 82,
        'anomaly_rate': 0.45,
        'max_anomaly_score': 0.96,
        'avg_anomaly_score': 0.62,
        'top_tactics': {
            'Reconnaissance': 25,
            'Impact': 18,
            'Credential Access': 12,
            'Command and Control': 8,
            'Defense Evasion': 5
        },
        'top_techniques': {
            'T1046': 25,
            'T1498': 18,
            'T1110': 12,
            'T1572': 8,
            'T1222': 5
        },
        'severity_distribution': {
            'Critical': 15,
            'High': 28,
            'Medium': 18,
            'Low': 7
        }
    }
    
    print("=" * 80)
    print("TESTING THREAT SUMMARIZER - MOCK BACKEND")
    print("=" * 80)
    
    summary = summarizer.generate_summary(
        threat_data=test_data,
        provider="Mock (Testing)",
        model_name="mock"
    )
    
    print("\n" + summary)
