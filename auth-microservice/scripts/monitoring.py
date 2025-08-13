#!/usr/bin/env python3
"""
Monitoring and Alerting Script for Auth Microservice
Monitors service health, performance, and security metrics
"""

import os
import sys
import json
import time
import requests
import smtplib
import psutil
from datetime import datetime, timedelta
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging

# Add the project root to the path
sys.path.append(str(Path(__file__).parent.parent / 'src'))

class ServiceMonitor:
    def __init__(self, config_file='monitoring_config.json'):
        self.config = self._load_config(config_file)
        self.setup_logging()
        self.alerts = []
        self.metrics = {}
    
    def _load_config(self, config_file):
        """Load monitoring configuration"""
        default_config = {
            'service_url': 'http://localhost:5000',
            'check_interval': 60,  # seconds
            'alert_thresholds': {
                'response_time_ms': 1000,
                'memory_usage_percent': 80,
                'cpu_usage_percent': 80,
                'disk_usage_percent': 85,
                'error_rate_percent': 5
            },
            'email_alerts': {
                'enabled': False,
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'username': '',
                'password': '',
                'recipients': []
            },
            'slack_alerts': {
                'enabled': False,
                'webhook_url': ''
            }
        }
        
        config_path = Path(__file__).parent / config_file
        if config_path.exists():
            with open(config_path) as f:
                user_config = json.load(f)
                default_config.update(user_config)
        
        return default_config
    
    def setup_logging(self):
        """Setup logging for monitoring"""
        log_dir = Path(__file__).parent.parent / 'logs'
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / 'monitoring.log'
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger(__name__)
    
    def check_service_health(self):
        """Check service health and availability"""
        try:
            start_time = time.time()
            response = requests.get(
                f"{self.config['service_url']}/health",
                timeout=10
            )
            response_time = (time.time() - start_time) * 1000  # Convert to ms
            
            if response.status_code == 200:
                health_data = response.json()
                
                self.metrics['service_status'] = 'healthy'
                self.metrics['response_time_ms'] = response_time
                self.metrics['last_check'] = datetime.utcnow().isoformat()
                
                # Check response time threshold
                if response_time > self.config['alert_thresholds']['response_time_ms']:
                    self.add_alert(
                        'performance',
                        f"High response time: {response_time:.2f}ms",
                        'warning'
                    )
                
                # Check database and Redis health
                checks = health_data.get('checks', {})
                for service, status in checks.items():
                    if status != 'healthy':
                        self.add_alert(
                            'service',
                            f"{service.title()} service unhealthy",
                            'critical'
                        )
                
                self.logger.info(f"Health check passed - Response time: {response_time:.2f}ms")
                return True
            
            else:
                self.metrics['service_status'] = 'unhealthy'
                self.add_alert(
                    'service',
                    f"Service returned HTTP {response.status_code}",
                    'critical'
                )
                return False
        
        except requests.exceptions.RequestException as e:
            self.metrics['service_status'] = 'unreachable'
            self.add_alert(
                'service',
                f"Service unreachable: {str(e)}",
                'critical'
            )
            self.logger.error(f"Health check failed: {e}")
            return False
    
    def check_system_resources(self):
        """Check system resource usage"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            self.metrics['cpu_usage_percent'] = cpu_percent
            
            if cpu_percent > self.config['alert_thresholds']['cpu_usage_percent']:
                self.add_alert(
                    'resource',
                    f"High CPU usage: {cpu_percent:.1f}%",
                    'warning'
                )
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            self.metrics['memory_usage_percent'] = memory_percent
            self.metrics['memory_available_mb'] = memory.available / (1024 * 1024)
            
            if memory_percent > self.config['alert_thresholds']['memory_usage_percent']:
                self.add_alert(
                    'resource',
                    f"High memory usage: {memory_percent:.1f}%",
                    'warning'
                )
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            self.metrics['disk_usage_percent'] = disk_percent
            self.metrics['disk_free_gb'] = disk.free / (1024 ** 3)
            
            if disk_percent > self.config['alert_thresholds']['disk_usage_percent']:
                self.add_alert(
                    'resource',
                    f"High disk usage: {disk_percent:.1f}%",
                    'warning'
                )
            
            # Network connections (if service is running)
            try:
                connections = [
                    conn for conn in psutil.net_connections() 
                    if conn.laddr.port in [5000, 5432, 6379]  # App, PostgreSQL, Redis
                ]
                self.metrics['active_connections'] = len(connections)
            except (psutil.AccessDenied, AttributeError):
                self.metrics['active_connections'] = 'unavailable'
            
            self.logger.info(
                f"System resources - CPU: {cpu_percent:.1f}%, "
                f"Memory: {memory_percent:.1f}%, Disk: {disk_percent:.1f}%"
            )
            
        except Exception as e:
            self.logger.error(f"Failed to check system resources: {e}")
    
    def check_application_metrics(self):
        """Check application-specific metrics"""
        try:
            response = requests.get(
                f"{self.config['service_url']}/metrics",
                timeout=5
            )
            
            if response.status_code == 200:
                app_metrics = response.json().get('metrics', {})
                self.metrics.update(app_metrics)
                
                self.logger.info(f"Application metrics: {app_metrics}")
            else:
                self.add_alert(
                    'metrics',
                    f"Failed to retrieve application metrics: HTTP {response.status_code}",
                    'warning'
                )
        
        except requests.exceptions.RequestException as e:
            self.add_alert(
                'metrics',
                f"Failed to retrieve application metrics: {str(e)}",
                'warning'
            )
    
    def check_log_errors(self):
        """Check for recent errors in log files"""
        try:
            log_file = Path(__file__).parent.parent / 'logs' / 'auth_service.log'
            
            if not log_file.exists():
                return
            
            # Check for errors in the last 5 minutes
            current_time = datetime.utcnow()
            error_count = 0
            
            with open(log_file, 'r') as f:
                lines = f.readlines()
                
                # Check last 100 lines for recent errors
                for line in lines[-100:]:
                    if 'ERROR' in line or 'CRITICAL' in line:
                        error_count += 1
            
            self.metrics['recent_errors'] = error_count
            
            # Calculate error rate (rough estimate)
            total_requests = self.metrics.get('total_requests', 100)  # Default assumption
            error_rate = (error_count / total_requests) * 100 if total_requests > 0 else 0
            
            if error_rate > self.config['alert_thresholds']['error_rate_percent']:
                self.add_alert(
                    'application',
                    f"High error rate: {error_rate:.1f}%",
                    'critical'
                )
        
        except Exception as e:
            self.logger.error(f"Failed to check log errors: {e}")
    
    def check_security_metrics(self):
        """Check security-related metrics"""
        try:
            # This would connect to your database to check for security events
            # For now, we'll simulate some basic checks
            
            # Check for failed login attempts (would query database)
            # failed_logins = get_recent_failed_logins()  # Implement this
            
            # Check for suspicious activity patterns
            # suspicious_activity = detect_suspicious_patterns()  # Implement this
            
            # For demonstration, we'll add a placeholder
            self.metrics['security_status'] = 'monitored'
            
            # You would implement actual security checks here
            # Example checks:
            # - Failed login attempts spike
            # - Multiple requests from same IP
            # - Unusual access patterns
            # - Token generation/usage anomalies
            
        except Exception as e:
            self.logger.error(f"Failed to check security metrics: {e}")
    
    def add_alert(self, category, message, severity='info'):
        """Add an alert"""
        alert = {
            'timestamp': datetime.utcnow().isoformat(),
            'category': category,
            'message': message,
            'severity': severity
        }
        
        self.alerts.append(alert)
        self.logger.warning(f"ALERT [{severity.upper()}] {category}: {message}")
    
    def send_alerts(self):
        """Send alerts via configured channels"""
        if not self.alerts:
            return
        
        critical_alerts = [a for a in self.alerts if a['severity'] == 'critical']
        warning_alerts = [a for a in self.alerts if a['severity'] == 'warning']
        
        if critical_alerts or len(warning_alerts) > 5:  # Send if critical or many warnings
            if self.config['email_alerts']['enabled']:
                self.send_email_alerts()
            
            if self.config['slack_alerts']['enabled']:
                self.send_slack_alerts()
    
    def send_email_alerts(self):
        """Send email alerts"""
        try:
            smtp_config = self.config['email_alerts']
            
            msg = MIMEMultipart()
            msg['From'] = smtp_config['username']
            msg['To'] = ', '.join(smtp_config['recipients'])
            msg['Subject'] = f"Auth Microservice Alert - {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}"
            
            # Create alert summary
            alert_summary = self.create_alert_summary()
            msg.attach(MIMEText(alert_summary, 'plain'))
            
            # Send email
            server = smtplib.SMTP(smtp_config['smtp_server'], smtp_config['smtp_port'])
            server.starttls()
            server.login(smtp_config['username'], smtp_config['password'])
            server.send_message(msg)
            server.quit()
            
            self.logger.info("Email alerts sent successfully")
        
        except Exception as e:
            self.logger.error(f"Failed to send email alerts: {e}")
    
    def send_slack_alerts(self):
        """Send Slack alerts"""
        try:
            slack_config = self.config['slack_alerts']
            
            alert_summary = self.create_alert_summary()
            
            payload = {
                'text': f"🚨 Auth Microservice Alerts",
                'attachments': [{
                    'color': 'danger',
                    'text': alert_summary
                }]
            }
            
            response = requests.post(
                slack_config['webhook_url'],
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                self.logger.info("Slack alerts sent successfully")
            else:
                self.logger.error(f"Failed to send Slack alerts: HTTP {response.status_code}")
        
        except Exception as e:
            self.logger.error(f"Failed to send Slack alerts: {e}")
    
    def create_alert_summary(self):
        """Create a summary of all alerts"""
        summary = f"Auth Microservice Alert Summary - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        critical_alerts = [a for a in self.alerts if a['severity'] == 'critical']
        warning_alerts = [a for a in self.alerts if a['severity'] == 'warning']
        
        if critical_alerts:
            summary += "🔴 CRITICAL ALERTS:\n"
            for alert in critical_alerts:
                summary += f"  • {alert['category']}: {alert['message']}\n"
            summary += "\n"
        
        if warning_alerts:
            summary += "⚠️ WARNING ALERTS:\n"
            for alert in warning_alerts:
                summary += f"  • {alert['category']}: {alert['message']}\n"
            summary += "\n"
        
        # Add system metrics
        summary += "📊 CURRENT METRICS:\n"
        for key, value in self.metrics.items():
            if isinstance(value, float):
                summary += f"  • {key}: {value:.2f}\n"
            else:
                summary += f"  • {key}: {value}\n"
        
        return summary
    
    def save_metrics(self):
        """Save metrics to file for historical tracking"""
        metrics_dir = Path(__file__).parent.parent / 'logs' / 'metrics'
        metrics_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        metrics_file = metrics_dir / f"metrics_{timestamp}.json"
        
        data = {
            'timestamp': datetime.utcnow().isoformat(),
            'metrics': self.metrics,
            'alerts': self.alerts
        }
        
        with open(metrics_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def run_monitoring_cycle(self):
        """Run a complete monitoring cycle"""
        self.logger.info("Starting monitoring cycle")
        
        # Clear previous alerts
        self.alerts = []
        
        # Run all checks
        self.check_service_health()
        self.check_system_resources()
        self.check_application_metrics()
        self.check_log_errors()
        self.check_security_metrics()
        
        # Send alerts if needed
        self.send_alerts()
        
        # Save metrics
        self.save_metrics()
        
        self.logger.info(f"Monitoring cycle completed - {len(self.alerts)} alerts generated")
    
    def run_continuous_monitoring(self):
        """Run continuous monitoring with configured interval"""
        self.logger.info(f"Starting continuous monitoring (interval: {self.config['check_interval']}s)")
        
        try:
            while True:
                self.run_monitoring_cycle()
                time.sleep(self.config['check_interval'])
        
        except KeyboardInterrupt:
            self.logger.info("Monitoring stopped by user")
        except Exception as e:
            self.logger.error(f"Monitoring error: {e}")

def create_default_config():
    """Create default monitoring configuration file"""
    config = {
        'service_url': 'http://localhost:5000',
        'check_interval': 60,
        'alert_thresholds': {
            'response_time_ms': 1000,
            'memory_usage_percent': 80,
            'cpu_usage_percent': 80,
            'disk_usage_percent': 85,
            'error_rate_percent': 5
        },
        'email_alerts': {
            'enabled': False,
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'username': 'your-email@gmail.com',
            'password': 'your-app-password',
            'recipients': ['admin@yourcompany.com']
        },
        'slack_alerts': {
            'enabled': False,
            'webhook_url': 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'
        }
    }
    
    config_file = Path(__file__).parent / 'monitoring_config.json'
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f"Default monitoring configuration created: {config_file}")
    print("Please edit the configuration file to enable alerts and set your credentials.")

def main():
    """Main function"""
    if len(sys.argv) > 1 and sys.argv[1] == '--create-config':
        create_default_config()
        return
    
    print("🔍 Auth Microservice Monitoring")
    print("=" * 50)
    
    monitor = ServiceMonitor()
    
    if len(sys.argv) > 1 and sys.argv[1] == '--once':
        # Run once and exit
        monitor.run_monitoring_cycle()
    else:
        # Run continuous monitoring
        monitor.run_continuous_monitoring()

if __name__ == "__main__":
    main()
