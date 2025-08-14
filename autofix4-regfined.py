#!/usr/bin/env python3

import argparse
import asyncio
import configparser
import csv
import json
import logging
import os
import re
import sqlite3
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set, Any
import hashlib
import signal
import sys
from threading import Lock

import requests
from packaging import version
from tqdm import tqdm
import yaml
import click
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import pandas as pd

# Constants
DOCKER_HUB_URL = "https://registry.hub.docker.com/v2/repositories/library/{image}/tags?page_size=100"
CACHE_EXPIRY_HOURS = 24
DATABASE_SCHEMA_VERSION = "1.0"

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vulnerability_scanner.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class VulnerabilityMetrics:
    """Enhanced vulnerability metrics with weighted scoring"""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0
    
    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.unknown
    
    @property
    def high_critical(self) -> int:
        return self.critical + self.high
    
    @property
    def weighted_score(self) -> float:
        """Calculate severity-weighted score (higher is worse)"""
        return (self.critical * 10.0) + (self.high * 7.0) + (self.medium * 4.0) + (self.low * 1.0)

@dataclass
class ScanResult:
    """Enhanced scan result with detailed tracking"""
    tag: str
    base_metrics: VulnerabilityMetrics
    built_metrics: VulnerabilityMetrics
    scan_duration: float
    build_success: bool
    vulnerabilities: List[Dict]
    fixed_vulns: Set[str]
    introduced_vulns: Set[str]
    timestamp: str
    
class ProgressTracker:
    """Thread-safe progress tracking"""
    def __init__(self):
        self.lock = Lock()
        self.progress_bars: Dict[str, tqdm] = {}
    
    def create_progress_bar(self, name: str, total: int, desc: str = "") -> tqdm:
        with self.lock:
            pbar = tqdm(total=total, desc=desc, position=len(self.progress_bars))
            self.progress_bars[name] = pbar
            return pbar
    
    def update_progress(self, name: str, amount: int = 1):
        with self.lock:
            if name in self.progress_bars:
                self.progress_bars[name].update(amount)
    
    def close_all(self):
        with self.lock:
            for pbar in self.progress_bars.values():
                pbar.close()
            self.progress_bars.clear()

class DatabaseManager:
    """SQLite database for scan history"""
    def __init__(self, db_path: str = "vulnerability_scans.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                image_name TEXT NOT NULL,
                tag TEXT NOT NULL,
                scan_timestamp TEXT NOT NULL,
                vulnerabilities_json TEXT,
                metrics_json TEXT,
                build_success BOOLEAN,
                scan_duration REAL,
                hash TEXT UNIQUE
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_image_tag ON scan_history(image_name, tag)
        """)
        
        conn.commit()
        conn.close()
    
    def store_scan_result(self, image_name: str, result: ScanResult):
        """Store scan result with duplicate prevention"""
        result_hash = hashlib.md5(f"{image_name}:{result.tag}:{result.timestamp}".encode()).hexdigest()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO scan_history 
                (image_name, tag, scan_timestamp, vulnerabilities_json, metrics_json, 
                 build_success, scan_duration, hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                image_name, result.tag, result.timestamp,
                json.dumps(result.vulnerabilities),
                json.dumps(asdict(result.built_metrics)),
                result.build_success, result.scan_duration, result_hash
            ))
            conn.commit()
        except sqlite3.IntegrityError:
            logger.debug(f"Scan result already exists for {image_name}:{result.tag}")
        finally:
            conn.close()
    
    def get_scan_history(self, image_name: str, days: int = 30) -> List[Dict]:
        """Retrieve scan history for analysis"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cutoff_date = datetime.now() - timedelta(days=days)
        cursor.execute("""
            SELECT * FROM scan_history 
            WHERE image_name = ? AND scan_timestamp >= ?
            ORDER BY scan_timestamp DESC
        """, (image_name, cutoff_date.isoformat()))
        
        columns = [desc[0] for desc in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]
        conn.close()
        return results

class CacheManager:
    """Smart caching system for scan results"""
    def __init__(self, cache_dir: str = ".vulnerability_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
    
    def get_cache_key(self, image: str) -> str:
        return hashlib.sha256(image.encode()).hexdigest()
    
    def is_cached(self, image: str) -> bool:
        cache_file = self.cache_dir / f"{self.get_cache_key(image)}.json"
        if not cache_file.exists():
            return False
        
        # Check if cache is expired
        modified_time = datetime.fromtimestamp(cache_file.stat().st_mtime)
        return datetime.now() - modified_time < timedelta(hours=CACHE_EXPIRY_HOURS)
    
    def get_cached_result(self, image: str) -> Optional[List[Dict]]:
        if not self.is_cached(image):
            return None
        
        cache_file = self.cache_dir / f"{self.get_cache_key(image)}.json"
        try:
            with open(cache_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to read cache for {image}: {e}")
            return None
    
    def cache_result(self, image: str, vulnerabilities: List[Dict]):
        cache_file = self.cache_dir / f"{self.get_cache_key(image)}.json"
        try:
            with open(cache_file, 'w') as f:
                json.dump(vulnerabilities, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to cache result for {image}: {e}")

class ConfigManager:
    """Configuration management with validation"""
    def __init__(self, config_path: str = "vulnerability_scanner.yaml"):
        self.config_path = config_path
        self.config = self.load_config()
    
    def load_config(self) -> Dict:
        default_config = {
            'scanning': {
                'max_parallel_scans': 5,
                'scan_timeout': 300,
                'max_tags_to_test': 10,
                'skip_tags_patterns': ['latest', 'edge', 'dev', 'alpha', 'beta', 'rc'],
                'enable_cache': True
            },
            'severity': {
                'fail_on_critical': True,
                'fail_on_high': False,
                'weights': {'critical': 10.0, 'high': 7.0, 'medium': 4.0, 'low': 1.0}
            },
            'output': {
                'generate_charts': True,
                'export_formats': ['json', 'csv', 'html'],
                'charts_format': 'html'
            },
            'notifications': {
                'webhook_url': None,
                'slack_webhook': None,
                'email_smtp': None
            },
            'registries': {
                'docker_hub': {'url': 'https://registry.hub.docker.com'},
                'private': {}
            }
        }
        
        if Path(self.config_path).exists():
            try:
                with open(self.config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
                    if user_config:
                        # Merge configurations
                        return self._merge_configs(default_config, user_config)
            except Exception as e:
                logger.warning(f"Failed to load config from {self.config_path}: {e}")
        
        return default_config
    
    def _merge_configs(self, default: Dict, user: Dict) -> Dict:
        """Deep merge user config with defaults"""
        for key, value in user.items():
            if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                default[key] = self._merge_configs(default[key], value)
            else:
                default[key] = value
        return default

class WebhookNotifier:
    """Webhook notification system"""
    def __init__(self, webhook_url: Optional[str] = None):
        self.webhook_url = webhook_url
    
    def send_notification(self, payload: Dict):
        if not self.webhook_url:
            return
        
        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10,
                headers={'Content-Type': 'application/json'}
            )
            response.raise_for_status()
            logger.info(f"Webhook notification sent successfully")
        except Exception as e:
            logger.error(f"Failed to send webhook notification: {e}")

class ReportGenerator:
    """Enhanced reporting with multiple formats and visualizations"""
    def __init__(self, config: Dict):
        self.config = config
    
    def generate_vulnerability_charts(self, results: List[ScanResult], output_dir: str):
        """Generate comprehensive vulnerability visualization charts"""
        if not self.config.get('output', {}).get('generate_charts', True):
            return
        
        if not results:
            logger.warning("No results to generate charts for")
            return
            
        try:
            output_path = Path(output_dir)
            output_path.mkdir(exist_ok=True)
            
            # Create DataFrame from results
            data = []
            for result in results:
                data.append({
                    'tag': result.tag,
                    'critical': result.built_metrics.critical,
                    'high': result.built_metrics.high,
                    'medium': result.built_metrics.medium,
                    'low': result.built_metrics.low,
                    'total': result.built_metrics.total,
                    'weighted_score': result.built_metrics.weighted_score,
                    'build_success': result.build_success
                })
            
            df = pd.DataFrame(data)
            
            # 1. Vulnerability Count by Tag (Stacked Bar Chart)
            fig1 = go.Figure()
            fig1.add_trace(go.Bar(name='Critical', x=df['tag'], y=df['critical'], marker_color='red'))
            fig1.add_trace(go.Bar(name='High', x=df['tag'], y=df['high'], marker_color='orange'))
            fig1.add_trace(go.Bar(name='Medium', x=df['tag'], y=df['medium'], marker_color='yellow'))
            fig1.add_trace(go.Bar(name='Low', x=df['tag'], y=df['low'], marker_color='blue'))
            
            fig1.update_layout(
                title='Vulnerability Count by Tag',
                xaxis_title='Image Tag',
                yaxis_title='Number of Vulnerabilities',
                barmode='stack'
            )
            fig1.write_html(output_path / "vulnerability_count_by_tag.html")
            
            # 2. Weighted Security Score Comparison
            fig2 = go.Figure()
            fig2.add_trace(go.Scatter(
                x=df['tag'],
                y=df['weighted_score'],
                mode='lines+markers',
                name='Weighted Security Score',
                line=dict(color='red', width=2),
                marker=dict(size=8)
            ))
            
            fig2.update_layout(
                title='Security Score Trend (Lower is Better)',
                xaxis_title='Image Tag',
                yaxis_title='Weighted Security Score'
            )
            fig2.write_html(output_path / "security_score_trend.html")
            
            # 3. Build Success vs Security Metrics
            successful_builds = df[df['build_success'] == True]
            if not successful_builds.empty:
                fig3 = px.scatter(
                    successful_builds, 
                    x='total', 
                    y='weighted_score',
                    hover_data=['tag', 'critical', 'high'],
                    title='Total Vulnerabilities vs Weighted Score (Successful Builds Only)'
                )
                fig3.write_html(output_path / "vulnerability_scatter.html")
            
            logger.info(f"Generated vulnerability charts in {output_path}")
        except Exception as e:
            logger.error(f"Failed to generate charts: {e}")
    
    def export_csv_report(self, results: List[ScanResult], output_file: str):
        """Export detailed CSV report"""
        try:
            with open(output_file, 'w', newline='') as csvfile:
                fieldnames = [
                    'tag', 'build_success', 'scan_duration',
                    'critical', 'high', 'medium', 'low', 'total',
                    'weighted_score', 'fixed_count', 'introduced_count'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for result in results:
                    writer.writerow({
                        'tag': result.tag,
                        'build_success': result.build_success,
                        'scan_duration': result.scan_duration,
                        'critical': result.built_metrics.critical,
                        'high': result.built_metrics.high,
                        'medium': result.built_metrics.medium,
                        'low': result.built_metrics.low,
                        'total': result.built_metrics.total,
                        'weighted_score': result.built_metrics.weighted_score,
                        'fixed_count': len(result.fixed_vulns),
                        'introduced_count': len(result.introduced_vulns)
                    })
            logger.info(f"CSV report saved to {output_file}")
        except Exception as e:
            logger.error(f"Failed to generate CSV report: {e}")
    
    def generate_html_report(self, results: List[ScanResult], output_file: str):
        """Generate comprehensive HTML report"""
        try:
            html_template = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Vulnerability Scan Report</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
                    .metrics { display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }
                    .metric-card { background: #fff; border: 1px solid #ddd; padding: 15px; border-radius: 5px; flex: 1; min-width: 200px; }
                    .critical { border-left: 5px solid #dc3545; }
                    .high { border-left: 5px solid #fd7e14; }
                    .medium { border-left: 5px solid #ffc107; }
                    .low { border-left: 5px solid #17a2b8; }
                    table { width: 100%; border-collapse: collapse; margin: 20px 0; }
                    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                    th { background-color: #f2f2f2; }
                    .success { color: green; }
                    .failure { color: red; }
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>Docker Image Vulnerability Scan Report</h1>
                    <p>Generated on: {timestamp}</p>
                    <p>Total tags scanned: {total_tags}</p>
                    <p>Successful builds: {successful_builds}</p>
                </div>
                
                <div class="metrics">
                    <div class="metric-card critical">
                        <h3>Critical Vulnerabilities</h3>
                        <p>{total_critical}</p>
                    </div>
                    <div class="metric-card high">
                        <h3>High Vulnerabilities</h3>
                        <p>{total_high}</p>
                    </div>
                    <div class="metric-card medium">
                        <h3>Medium Vulnerabilities</h3>
                        <p>{total_medium}</p>
                    </div>
                    <div class="metric-card low">
                        <h3>Low Vulnerabilities</h3>
                        <p>{total_low}</p>
                    </div>
                </div>
                
                <h2>Detailed Results</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Tag</th>
                            <th>Build Success</th>
                            <th>Critical</th>
                            <th>High</th>
                            <th>Medium</th>
                            <th>Low</th>
                            <th>Total</th>
                            <th>Weighted Score</th>
                            <th>Scan Duration (s)</th>
                        </tr>
                    </thead>
                    <tbody>
                        {table_rows}
                    </tbody>
                </table>
            </body>
            </html>
            """
            
            # Calculate summary metrics
            total_critical = sum(r.built_metrics.critical for r in results)
            total_high = sum(r.built_metrics.high for r in results)
            total_medium = sum(r.built_metrics.medium for r in results)
            total_low = sum(r.built_metrics.low for r in results)
            successful_builds = sum(1 for r in results if r.build_success)
            
            # Generate table rows
            table_rows = ""
            for result in results:
                status_class = "success" if result.build_success else "failure"
                status_text = "✓" if result.build_success else "✗"
                
                table_rows += f"""
                    <tr>
                        <td>{result.tag}</td>
                        <td class="{status_class}">{status_text}</td>
                        <td>{result.built_metrics.critical}</td>
                        <td>{result.built_metrics.high}</td>
                        <td>{result.built_metrics.medium}</td>
                        <td>{result.built_metrics.low}</td>
                        <td>{result.built_metrics.total}</td>
                        <td>{result.built_metrics.weighted_score:.2f}</td>
                        <td>{result.scan_duration:.2f}</td>
                    </tr>
                """
            
            html_content = html_template.format(
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                total_tags=len(results),
                successful_builds=successful_builds,
                total_critical=total_critical,
                total_high=total_high,
                total_medium=total_medium,
                total_low=total_low,
                table_rows=table_rows
            )
            
            with open(output_file, 'w') as f:
                f.write(html_content)
            logger.info(f"HTML report saved to {output_file}")
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")

def parse_dockerfile_base_image(dockerfile_path: str) -> Tuple[str, str, str]:
    """
    Parse Dockerfile and extract base image information safely.
    
    Returns:
        Tuple of (full_base_image, base_name, tag)
    
    Raises:
        ValueError: If Dockerfile is invalid or FROM line is malformed
    """
    if not os.path.exists(dockerfile_path):
        raise ValueError(f"Dockerfile not found: {dockerfile_path}")
    
    with open(dockerfile_path, 'r') as f:
        content = f.read()
    
    # Find FROM line (case insensitive, handle comments)
    lines = [line.strip() for line in content.split('\n')]
    from_line = None
    
    for line in lines:
        # Skip comments and empty lines
        if not line or line.startswith('#'):
            continue
        # Check for FROM instruction (must be first non-comment instruction)
        if line.upper().startswith('FROM '):
            from_line = line
            break
        # If we hit any other instruction first, it's invalid
        elif re.match(r'^[A-Z]+\s+', line.upper()):
            break
    
    if not from_line:
        raise ValueError("No valid FROM instruction found in Dockerfile")
    
    # Extract image part from FROM line
    parts = from_line.split(None, 1)  # Split on whitespace, max 1 split
    if len(parts) < 2:
        raise ValueError(f"FROM instruction missing image name: {from_line}")
    
    # Handle multi-stage builds and platform flags
    image_part = parts[1]
    
    # Remove 'AS stage_name' if present
    if ' as ' in image_part.lower():
        image_part = image_part.split(' as ')[0].strip()
    elif ' AS ' in image_part:
        image_part = image_part.split(' AS ')[0].strip()
    
    # Remove platform flag if present
    if image_part.startswith('--platform='):
        parts = image_part.split(None, 1)
        if len(parts) > 1:
            image_part = parts[1]
        else:
            raise ValueError("Platform flag specified but no image name")
    
    image_part = image_part.strip()
    
    if not image_part:
        raise ValueError("Empty image name in FROM instruction")
    
    # Add default tag if missing
    if ':' not in image_part and '@' not in image_part:  # Handle digest format too
        full_image = f"{image_part}:latest"
        base_name = image_part
        tag = "latest"
    else:
        full_image = image_part
        if ':' in image_part:
            base_name, tag = image_part.split(':', 1)
        else:  # digest format
            base_name = image_part.split('@')[0]
            tag = image_part.split('@')[1]
    
    return full_image, base_name, tag

class EnterpriseVulnerabilityScanner:
    """Main enterprise scanner class with all advanced features"""
    
    def __init__(self, config_path: str = "vulnerability_scanner.yaml"):
        try:
            self.config_manager = ConfigManager(config_path)
            self.config = self.config_manager.config
            self.cache_manager = CacheManager()
            self.db_manager = DatabaseManager()
            self.progress_tracker = ProgressTracker()
            self.webhook_notifier = WebhookNotifier(
                self.config.get('notifications', {}).get('webhook_url')
            )
            self.report_generator = ReportGenerator(self.config)
            
            # Resource monitoring
            self.resource_lock = Lock()
            self.active_scans = 0
            self.max_parallel_scans = self.config.get('scanning', {}).get('max_parallel_scans', 5)
            
            # Graceful shutdown handling
            signal.signal(signal.SIGINT, self.signal_handler)
            signal.signal(signal.SIGTERM, self.signal_handler)
            self.shutdown_requested = False
        except Exception as e:
            logger.error(f"Failed to initialize scanner: {e}")
            raise
    
    def signal_handler(self, signum, frame):
        """Handle graceful shutdown"""
        logger.info(f"Received signal {signum}, initiating graceful shutdown...")
        self.shutdown_requested = True
        self.cleanup_resources()
        sys.exit(0)
    
    def cleanup_resources(self):
        """Clean up resources and temporary files"""
        try:
            self.progress_tracker.close_all()
            
            # Clean up any temporary Docker images
            try:
                result = subprocess.run(
                    ["docker", "images", "--filter", "dangling=true", "-q"],
                    capture_output=True, text=True
                )
                if result.stdout.strip():
                    subprocess.run(
                        ["docker", "rmi"] + result.stdout.strip().split(),
                        capture_output=True
                    )
                    logger.info("Cleaned up dangling Docker images")
            except Exception as e:
                logger.warning(f"Failed to clean up Docker images: {e}")
        except Exception as e:
            logger.warning(f"Error during cleanup: {e}")
    
    def run_cmd_with_timeout(self, cmd: List[str], timeout: int = 300, show_output: bool = False) -> str:
        """Execute command with timeout and resource monitoring"""
        try:
            logger.debug(f"Running command: {' '.join(cmd)}")
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=timeout,
                check=True
            )
            
            if show_output and result.stdout:
                logger.info(result.stdout)
            
            return result.stdout.strip()
            
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out after {timeout}s: {' '.join(cmd)}")
            raise
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {' '.join(cmd)}")
            logger.error(f"Return code: {e.returncode}")
            logger.error(f"STDOUT: {e.stdout}")
            logger.error(f"STDERR: {e.stderr}")
            raise
    
    def scan_image_with_cache(self, image: str) -> List[Dict]:
        """Scan image with intelligent caching"""
        if self.config.get('scanning', {}).get('enable_cache', True):
            cached_result = self.cache_manager.get_cached_result(image)
            if cached_result is not None:
                logger.info(f"Using cached scan result for {image}")
                return cached_result
        
        # Perform actual scan
        with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as tmpfile:
            tmp_path = tmpfile.name
        
        try:
            timeout = self.config.get('scanning', {}).get('scan_timeout', 300)
            self.run_cmd_with_timeout([
                "trivy", "image", "--no-progress", "-f", "json", 
                "-o", tmp_path, image
            ], timeout=timeout)
            
            with open(tmp_path) as f:
                report = json.load(f)
            
            vulnerabilities = []
            for result in report.get("Results", []):
                for vuln in result.get("Vulnerabilities", []):
                    vulnerabilities.append(vuln)
            
            # Cache the result
            if self.config.get('scanning', {}).get('enable_cache', True):
                self.cache_manager.cache_result(image, vulnerabilities)
            
            return vulnerabilities
            
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
    
    def analyze_vulnerabilities(self, vulnerabilities: List[Dict]) -> VulnerabilityMetrics:
        """Enhanced vulnerability analysis with detailed categorization"""
        metrics = VulnerabilityMetrics()
        
        for vuln in vulnerabilities:
            severity = vuln.get("Severity", "UNKNOWN").upper()
            if severity == "CRITICAL":
                metrics.critical += 1
            elif severity == "HIGH":
                metrics.high += 1
            elif severity == "MEDIUM":
                metrics.medium += 1
            elif severity == "LOW":
                metrics.low += 1
            else:
                metrics.unknown += 1
        
        return metrics
    
    def smart_tag_filter(self, tags: List[str], current_tag: str) -> List[str]:
        """Intelligent tag filtering to skip obviously problematic versions"""
        skip_patterns = self.config.get('scanning', {}).get('skip_tags_patterns', [])
        max_tags = self.config.get('scanning', {}).get('max_tags_to_test', 10)
        
        # Filter out unwanted tags
        filtered_tags = []
        for tag in tags:
            skip = False
            for pattern in skip_patterns:
                if pattern.lower() in tag.lower():
                    skip = True
                    break
            if not skip:
                filtered_tags.append(tag)
        
        # Sort by version and take the most recent ones
        try:
            current_version = version.parse(current_tag)
            filtered_tags = [t for t in filtered_tags if version.parse(t) > current_version]
            filtered_tags = sorted(filtered_tags, key=version.parse, reverse=True)[:max_tags]
        except version.InvalidVersion:
            logger.warning(f"Invalid version format for current tag: {current_tag}")
            filtered_tags = filtered_tags[:max_tags]
        
        return filtered_tags
    
    def parallel_scan_tags(self, base_name: str, tags: List[str], 
                          dockerfile_path: str, build_context: str, 
                          image_name: str, current_vulnerabilities: List[Dict]) -> List[ScanResult]:
        """Parallel scanning of multiple tags with progress tracking"""
        
        if not tags:
            return []
        
        current_vuln_ids = set(v["VulnerabilityID"] for v in current_vulnerabilities)
        results = []
        
        # Create progress bar
        pbar = self.progress_tracker.create_progress_bar(
            "tag_scanning", len(tags), "Scanning tags"
        )
        
        with ThreadPoolExecutor(max_workers=self.max_parallel_scans) as executor:
            future_to_tag = {}
            
            for tag in tags:
                if self.shutdown_requested:
                    break
                    
                future = executor.submit(
                    self.scan_single_tag, 
                    base_name, tag, dockerfile_path, build_context, 
                    image_name, current_vuln_ids
                )
                future_to_tag[future] = tag
            
            for future in as_completed(future_to_tag):
                if self.shutdown_requested:
                    break
                    
                tag = future_to_tag[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        # Store in database
                        self.db_manager.store_scan_result(image_name, result)
                except Exception as e:
                    logger.error(f"Failed to scan tag {tag}: {e}")
                finally:
                    self.progress_tracker.update_progress("tag_scanning")
        
        pbar.close()
        return results
    
    def scan_single_tag(self, base_name: str, tag: str, dockerfile_path: str, 
                       build_context: str, image_name: str, current_vuln_ids: Set[str]) -> Optional[ScanResult]:
        """Scan a single tag with comprehensive error handling"""
        start_time = time.time()
        base_test_image = f"{base_name}:{tag}"
        built_test_image = f"{image_name}-test-{tag}"
        temp_dockerfile = None
        
        try:
            with self.resource_lock:
                self.active_scans += 1
            
            logger.info(f"Scanning tag: {tag}")
            
            # Scan base image
            try:
                base_vulns = self.scan_image_with_cache(base_test_image)
                base_metrics = self.analyze_vulnerabilities(base_vulns)
            except Exception as e:
                logger.warning(f"Failed to scan base image {base_test_image}: {e}")
                return None
            
            # Create temporary Dockerfile
            temp_dockerfile = dockerfile_path + f".temp-{tag}"
            with open(dockerfile_path, 'r') as f:
                content = f.read()
            
            updated_content = re.sub(
                r'^FROM\s+\S+',
                f'FROM {base_name}:{tag}',
                content,
                flags=re.MULTILINE
            )
            
            with open(temp_dockerfile, 'w') as f:
                f.write(updated_content)
            
            # Build and scan the application image
            build_success = False
            built_vulns = []
            
            try:
                timeout = self.config.get('scanning', {}).get('scan_timeout', 300)
                self.run_cmd_with_timeout([
                    "docker", "build", "-f", temp_dockerfile, 
                    "-t", built_test_image, build_context
                ], timeout=timeout)
                
                built_vulns = self.scan_image_with_cache(built_test_image)
                build_success = True
                
            except Exception as e:
                logger.warning(f"Failed to build/scan with tag {tag}: {e}")
            
            # Calculate vulnerability differences
            built_vuln_ids = set(v["VulnerabilityID"] for v in built_vulns)
            fixed_vulns = current_vuln_ids - built_vuln_ids
            introduced_vulns = built_vuln_ids - current_vuln_ids
            
            scan_duration = time.time() - start_time
            built_metrics = self.analyze_vulnerabilities(built_vulns)
            
            return ScanResult(
                tag=tag,
                base_metrics=base_metrics,
                built_metrics=built_metrics,
                scan_duration=scan_duration,
                build_success=build_success,
                vulnerabilities=built_vulns,
                fixed_vulns=fixed_vulns,
                introduced_vulns=introduced_vulns,
                timestamp=datetime.now().isoformat()
            )
            
        finally:
            # Cleanup
            if temp_dockerfile and os.path.exists(temp_dockerfile):
                os.remove(temp_dockerfile)
            
            # Remove test image
            try:
                subprocess.run(
                    ["docker", "rmi", built_test_image], 
                    capture_output=True, check=False
                )
            except:
                pass
            
            with self.resource_lock:
                self.active_scans -= 1
    
    def select_best_tag(self, results: List[ScanResult], current_metrics: VulnerabilityMetrics) -> Optional[ScanResult]:
        """Intelligent tag selection based on multiple criteria"""
        if not results:
            return None
        
        # Filter to only successful builds
        successful_results = [r for r in results if r.build_success]
        if not successful_results:
            logger.warning("No successful builds found in scan results")
            return None
        
        # Sort by multiple criteria:
        # 1. Weighted security score (lower is better)
        # 2. Total vulnerabilities (lower is better)  
        # 3. Build success rate
        successful_results.sort(key=lambda x: (
            x.built_metrics.weighted_score,
            x.built_metrics.total,
            -int(x.build_success)
        ))
        
        best_result = successful_results[0]
        
        # Only recommend if significantly better
        current_score = current_metrics.weighted_score
        improvement_threshold = 0.1  # 10% improvement threshold
        
        if (best_result.built_metrics.weighted_score < current_score * (1 - improvement_threshold) or
            best_result.built_metrics.high_critical < current_metrics.high_critical):
            return best_result
        
        return None

def create_sample_config():
    """Create a sample configuration file"""
    sample_config = """
# Enterprise Vulnerability Scanner Configuration

scanning:
  max_parallel_scans: 5
  scan_timeout: 300
  max_tags_to_test: 10
  skip_tags_patterns: 
    - "latest"
    - "edge" 
    - "dev"
    - "alpha"
    - "beta"
    - "rc"
  enable_cache: true

severity:
  fail_on_critical: true
  fail_on_high: false
  weights:
    critical: 10.0
    high: 7.0
    medium: 4.0
    low: 1.0

output:
  generate_charts: true
  export_formats: 
    - "json"
    - "csv" 
    - "html"
  charts_format: "html"

notifications:
  webhook_url: null
  slack_webhook: null
  email_smtp: null

registries:
  docker_hub:
    url: "https://registry.hub.docker.com"
  private: {}
"""
    
    with open("vulnerability_scanner.yaml", "w") as f:
        f.write(sample_config)
    print("Created sample configuration file: vulnerability_scanner.yaml")

@click.command()
@click.option('--image', required=True, help='Docker image to scan')
@click.option('--dockerfile', required=True, help='Path to Dockerfile')
@click.option('--build-context', required=True, help='Docker build context')
@click.option('--output-dir', default='./reports', help='Output directory for reports')
@click.option('--config', default='vulnerability_scanner.yaml', help='Configuration file path')
@click.option('--dry-run', is_flag=True, help='Preview changes without applying them')
@click.option('--interactive', is_flag=True, help='Interactive mode for tag selection')
@click.option('--create-config', is_flag=True, help='Create sample configuration file')
@click.option('--auto-fix', is_flag=True, help='Automatically apply the fix without prompting')
def main(image: str, dockerfile: str, build_context: str, output_dir: str, 
         config: str, dry_run: bool, interactive: bool, create_config: bool, auto_fix: bool):
    """Enterprise-grade Docker vulnerability scanner with advanced features"""
    
    if create_config:
        create_sample_config()
        return
    
    # Verify required files exist
    for path in [dockerfile, build_context]:
        if not os.path.exists(path):
            logger.error(f"Required path not found: {path}")
            return 1
    
    scanner = None
    try:
        scanner = EnterpriseVulnerabilityScanner(config)
        
        # Initial scan
        logger.info(f"Starting enterprise vulnerability scan for: {image}")
        
        initial_vulns = scanner.scan_image_with_cache(image)
        initial_metrics = scanner.analyze_vulnerabilities(initial_vulns)
        
        logger.info(f"Current image has {initial_metrics.total} vulnerabilities "
                   f"({initial_metrics.high_critical} HIGH/CRITICAL)")
        
        # Extract base image info using robust parser
        try:
            base_image, base_name, current_tag = parse_dockerfile_base_image(dockerfile)
            logger.info(f"Base image: {base_image}")
        except ValueError as e:
            logger.error(f"Dockerfile parsing error: {e}")
            return 1
        
        # Fetch and filter newer tags
        try:
            resp = requests.get(DOCKER_HUB_URL.format(image=base_name), timeout=30)
            resp.raise_for_status()
            tags_data = resp.json()
            
            all_tags = [t["name"] for t in tags_data["results"] 
                       if re.match(r"^\d+(\.\d+){1,2}$", t["name"])]
            
            newer_tags = scanner.smart_tag_filter(all_tags, current_tag)
            logger.info(f"Found {len(newer_tags)} candidate tags to test")
            
        except Exception as e:
            logger.error(f"Failed to fetch tags from Docker Hub: {e}")
            return 1
        
        if dry_run:
            logger.info("DRY RUN MODE - Would test the following tags:")
            for tag in newer_tags[:5]:  # Show first 5
                logger.info(f"  - {tag}")
            return 0
        
        # Parallel scanning of tags
        scan_results = scanner.parallel_scan_tags(
            base_name, newer_tags, dockerfile, build_context, image, initial_vulns
        )
        
        if not scan_results:
            logger.info("No successful scans found")
            return 0
        
        # Select best tag
        best_result = scanner.select_best_tag(scan_results, initial_metrics)
        
        if interactive and scan_results:
            # Interactive mode - let user choose
            print("\n=== Scan Results ===")
            print(f"{'Rank':<4} {'Tag':<15} {'Critical':<8} {'High':<6} {'Medium':<6} {'Low':<6} {'Total':<6} {'Score':<8}")
            print("-" * 70)
            
            sorted_results = sorted(scan_results, key=lambda x: x.built_metrics.weighted_score)
            for i, result in enumerate(sorted_results[:10], 1):
                print(f"{i:<4} {result.tag:<15} {result.built_metrics.critical:<8} "
                      f"{result.built_metrics.high:<6} {result.built_metrics.medium:<6} "
                      f"{result.built_metrics.low:<6} {result.built_metrics.total:<6} "
                      f"{result.built_metrics.weighted_score:<8.2f}")
            
            choice = input("\nSelect tag number (or press Enter for automatic selection): ").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(sorted_results):
                best_result = sorted_results[int(choice) - 1]

        # ============= IMPLEMENTATION LOGIC =============
        implementation_status = "not_needed"
        final_image_name = None
        final_metrics = initial_metrics
        
        if best_result and not dry_run:
            logger.info(f"🔄 IMPLEMENTING UPGRADE: {current_tag} → {best_result.tag}")
            
            try:
                # 1. Update the Dockerfile with the better base image
                logger.info("   Updating Dockerfile...")
                with open(dockerfile, 'r') as f:
                    original_content = f.read()
                
                # Create backup
                backup_path = dockerfile + ".backup"
                with open(backup_path, 'w') as f:
                    f.write(original_content)
                logger.info(f"   Created backup: {backup_path}")
                
                # Update FROM line
                updated_content = re.sub(
                    r'^FROM\s+\S+',
                    f'FROM {base_name}:{best_result.tag}',
                    original_content,
                    flags=re.MULTILINE
                )
                
                with open(dockerfile, 'w') as f:
                    f.write(updated_content)
                
                # 2. Build the final image with the new base
                logger.info("   Building final image with updated base...")
                final_image_name = f"{image}-fixed"
                
                scanner.run_cmd_with_timeout([
                    "docker", "build", "-f", dockerfile, 
                    "-t", final_image_name, build_context
                ], timeout=600)
                
                # 3. Verify the fix worked
                logger.info("   Verifying the fix...")
                final_vulns = scanner.scan_image_with_cache(final_image_name)
                final_metrics = scanner.analyze_vulnerabilities(final_vulns)
                
                logger.info(f"   ✅ VERIFICATION COMPLETE:")
                logger.info(f"      Original: {initial_metrics.high_critical} HIGH/CRITICAL vulns")
                logger.info(f"      Fixed:    {final_metrics.high_critical} HIGH/CRITICAL vulns")
                logger.info(f"      Improvement: {initial_metrics.high_critical - final_metrics.high_critical} vulnerabilities fixed")
                
                # 4. Handle image replacement
                if auto_fix:
                    scanner.run_cmd_with_timeout(["docker", "tag", final_image_name, image])
                    logger.info(f"   ✅ Replaced {image} with fixed version")
                elif not interactive:
                    # In non-interactive mode, create the fixed image but don't replace original
                    logger.info(f"   ✅ Fixed image created as: {final_image_name}")
                    logger.info(f"   💡 To replace original: docker tag {final_image_name} {image}")
                else:
                    tag_as_original = input(f"\nReplace original image '{image}' with fixed version? [y/N]: ").strip().lower()
                    if tag_as_original in ['y', 'yes']:
                        scanner.run_cmd_with_timeout(["docker", "tag", final_image_name, image])
                        logger.info(f"   ✅ Replaced {image} with fixed version")
                    else:
                        logger.info(f"   ✅ Fixed image available as: {final_image_name}")
                
                implementation_status = "completed"
                
            except Exception as e:
                logger.error(f"   ❌ IMPLEMENTATION FAILED: {e}")
                logger.info("   🔄 Restoring original Dockerfile...")
                
                # Restore original Dockerfile on failure
                if 'backup_path' in locals() and os.path.exists(backup_path):
                    with open(backup_path, 'r') as f:
                        content = f.read()
                    with open(dockerfile, 'w') as f:
                        f.write(content)
                
                implementation_status = "failed"
                final_metrics = initial_metrics
                
        elif best_result and dry_run:
            logger.info(f"🔍 DRY RUN - Would implement: {current_tag} → {best_result.tag}")
            implementation_status = "dry_run"
            
        else:
            logger.info(f"ℹ️  No implementation needed - current tag is optimal")
            implementation_status = "not_needed"
        
        # ============= END IMPLEMENTATION LOGIC =============
        
        # Generate comprehensive reports
        os.makedirs(output_dir, exist_ok=True)
        
        # JSON report (updated with implementation details)
        json_report = {
            "scan_timestamp": datetime.now().isoformat(),
            "base_image_before": base_image,
            "base_image_after": f"{base_name}:{best_result.tag if best_result else current_tag}",
            "initial_metrics": asdict(initial_metrics),
            "final_metrics": asdict(final_metrics),
            "best_result": asdict(best_result) if best_result else None,
            "all_results": [asdict(r) for r in scan_results],
            "recommendation": "upgrade" if best_result else "no_change",
            "implementation_status": implementation_status,
            "final_image": final_image_name,
            "vulnerabilities_actually_fixed": initial_metrics.high_critical - final_metrics.high_critical if final_metrics else 0
        }
        
        with open(f"{output_dir}/scan_report.json", 'w') as f:
            json.dump(json_report, f, indent=2, default=str)
        
        # CSV report
        scanner.report_generator.export_csv_report(scan_results, f"{output_dir}/scan_results.csv")
        
        # HTML report
        scanner.report_generator.generate_html_report(scan_results, f"{output_dir}/scan_report.html")
        
        # Generate charts
        scanner.report_generator.generate_vulnerability_charts(scan_results, f"{output_dir}/charts")
        
        # Send webhook notification
        if best_result:
            webhook_payload = {
                "event": "vulnerability_scan_completed",
                "image": image,
                "recommendation": "upgrade",
                "current_tag": current_tag,
                "recommended_tag": best_result.tag,
                "implementation_status": implementation_status,
                "improvement": {
                    "vulnerabilities_fixed": len(best_result.fixed_vulns),
                    "score_improvement": initial_metrics.weighted_score - best_result.built_metrics.weighted_score
                }
            }
            scanner.webhook_notifier.send_notification(webhook_payload)
        
        # Summary
        logger.info("=" * 60)
        logger.info("SCAN COMPLETE")
        logger.info("=" * 60)
        
        if best_result:
            if implementation_status == "completed":
                logger.info(f"✅ UPGRADE IMPLEMENTED: {current_tag} → {best_result.tag}")
                logger.info(f"   Vulnerabilities actually fixed: {initial_metrics.high_critical - final_metrics.high_critical}")
                logger.info(f"   Final HIGH/CRITICAL count: {final_metrics.high_critical}")
                if final_image_name:
                    logger.info(f"   Fixed image: {final_image_name}")
            elif implementation_status == "dry_run":
                logger.info(f"🔍 RECOMMENDED UPGRADE (DRY RUN): {current_tag} → {best_result.tag}")
                logger.info(f"   Would fix: {len(best_result.fixed_vulns)} vulnerabilities")
            elif implementation_status == "failed":
                logger.info(f"❌ UPGRADE FAILED: {current_tag} → {best_result.tag}")
                logger.info(f"   Dockerfile has been restored to original state")
            else:
                logger.info(f"✅ RECOMMENDED UPGRADE: {current_tag} → {best_result.tag}")
                logger.info(f"   Would fix: {len(best_result.fixed_vulns)} vulnerabilities")
        else:
            logger.info(f"✅ CURRENT TAG OPTIMAL: {current_tag}")
            logger.info("   No better alternatives found")
        
        logger.info(f"📊 Reports generated in: {output_dir}")
        logger.info(f"🎯 Tags tested: {len(newer_tags)}")
        logger.info(f"✅ Successful builds: {sum(1 for r in scan_results if r.build_success)}")
        
        return 0
        
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        logger.exception("Detailed error information:")
        return 1
    finally:
        if scanner:
            scanner.cleanup_resources()

if __name__ == "__main__":
    # Install required packages if not found
    try:
        import yaml
        import click
        import plotly
        import pandas as pd
    except ImportError as e:
        print(f"Missing required package: {e}")
        print("Please install with: pip install pyyaml click plotly pandas")
        sys.exit(1)
    
    exit(main())
