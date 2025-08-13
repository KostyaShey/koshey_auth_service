#!/usr/bin/env python3
"""
Security Audit Script for Auth Microservice
Performs security checks and generates audit reports
"""

import os
import sys
import json
import requests
import hashlib
import secrets
from datetime import datetime, timedelta
from pathlib import Path
import subprocess

# Add the project root to the path
sys.path.append(str(Path(__file__).parent.parent / 'src'))

class SecurityAuditor:
    def __init__(self, base_url='http://localhost:5000'):
        self.base_url = base_url
        self.results = []
        self.timestamp = datetime.utcnow().isoformat()
    
    def add_result(self, category, test_name, status, details=None, severity='info'):
        """Add audit result"""
        self.results.append({
            'category': category,
            'test_name': test_name,
            'status': status,
            'severity': severity,
            'details': details or {},
            'timestamp': datetime.utcnow().isoformat()
        })
    
    def check_environment_security(self):
        """Check environment configuration security"""
        print("🔒 Checking environment security...")
        
        env_file = Path(__file__).parent.parent / '.env'
        
        # Check if .env exists
        if not env_file.exists():
            self.add_result(
                'environment', 
                'env_file_exists', 
                'FAIL',
                {'message': '.env file not found'},
                'high'
            )
            return
        
        # Check .env permissions
        stat = env_file.stat()
        permissions = oct(stat.st_mode)[-3:]
        
        if permissions != '600':
            self.add_result(
                'environment',
                'env_file_permissions',
                'WARN',
                {'current_permissions': permissions, 'recommended': '600'},
                'medium'
            )
        else:
            self.add_result(
                'environment',
                'env_file_permissions',
                'PASS',
                {'permissions': permissions}
            )
        
        # Check required environment variables
        required_vars = [
            'SECRET_KEY', 'DATABASE_URL', 'REDIS_URL',
            'JWT_SECRET_KEY', 'JWT_PRIVATE_KEY_PATH', 'JWT_PUBLIC_KEY_PATH'
        ]
        
        with open(env_file) as f:
            env_content = f.read()
        
        missing_vars = []
        weak_secrets = []
        
        for var in required_vars:
            if var not in env_content:
                missing_vars.append(var)
            elif 'SECRET' in var:
                # Check secret strength
                lines = [line for line in env_content.split('\n') if line.startswith(f'{var}=')]
                if lines:
                    value = lines[0].split('=', 1)[1].strip().strip('"\'')
                    if len(value) < 32:
                        weak_secrets.append(var)
        
        if missing_vars:
            self.add_result(
                'environment',
                'required_env_vars',
                'FAIL',
                {'missing_variables': missing_vars},
                'high'
            )
        else:
            self.add_result(
                'environment',
                'required_env_vars',
                'PASS',
                {'all_required_vars_present': True}
            )
        
        if weak_secrets:
            self.add_result(
                'environment',
                'secret_strength',
                'WARN',
                {'weak_secrets': weak_secrets, 'min_length': 32},
                'medium'
            )
        else:
            self.add_result(
                'environment',
                'secret_strength',
                'PASS',
                {'all_secrets_strong': True}
            )
    
    def check_jwt_keys(self):
        """Check JWT key security"""
        print("🔑 Checking JWT key security...")
        
        keys_dir = Path(__file__).parent.parent / 'keys'
        
        if not keys_dir.exists():
            self.add_result(
                'jwt',
                'keys_directory_exists',
                'FAIL',
                {'message': 'Keys directory not found'},
                'high'
            )
            return
        
        # Check key files
        private_key = keys_dir / 'jwt_private.pem'
        public_key = keys_dir / 'jwt_public.pem'
        
        for key_file, key_type in [(private_key, 'private'), (public_key, 'public')]:
            if not key_file.exists():
                self.add_result(
                    'jwt',
                    f'{key_type}_key_exists',
                    'FAIL',
                    {'key_file': str(key_file)},
                    'high'
                )
            else:
                # Check permissions
                stat = key_file.stat()
                permissions = oct(stat.st_mode)[-3:]
                expected = '600' if key_type == 'private' else '644'
                
                if permissions != expected:
                    self.add_result(
                        'jwt',
                        f'{key_type}_key_permissions',
                        'WARN',
                        {'current': permissions, 'expected': expected},
                        'medium'
                    )
                else:
                    self.add_result(
                        'jwt',
                        f'{key_type}_key_permissions',
                        'PASS',
                        {'permissions': permissions}
                    )
    
    def check_api_security(self):
        """Check API endpoint security"""
        print("🛡️ Checking API security...")
        
        try:
            # Test health endpoint
            response = requests.get(f"{self.base_url}/health", timeout=5)
            
            if response.status_code == 200:
                self.add_result(
                    'api',
                    'health_endpoint_accessible',
                    'PASS',
                    {'status_code': response.status_code}
                )
                
                # Check security headers
                headers = response.headers
                security_headers = {
                    'X-Content-Type-Options': 'nosniff',
                    'X-Frame-Options': 'DENY',
                    'X-XSS-Protection': '1; mode=block'
                }
                
                missing_headers = []
                for header, expected in security_headers.items():
                    if header not in headers:
                        missing_headers.append(header)
                    elif headers[header] != expected:
                        missing_headers.append(f"{header} (incorrect value)")
                
                if missing_headers:
                    self.add_result(
                        'api',
                        'security_headers',
                        'WARN',
                        {'missing_headers': missing_headers},
                        'medium'
                    )
                else:
                    self.add_result(
                        'api',
                        'security_headers',
                        'PASS',
                        {'all_headers_present': True}
                    )
            else:
                self.add_result(
                    'api',
                    'health_endpoint_accessible',
                    'FAIL',
                    {'status_code': response.status_code},
                    'high'
                )
        
        except requests.exceptions.RequestException as e:
            self.add_result(
                'api',
                'service_availability',
                'FAIL',
                {'error': str(e)},
                'high'
            )
    
    def check_rate_limiting(self):
        """Check rate limiting functionality"""
        print("⏱️ Checking rate limiting...")
        
        try:
            # Test rate limiting on registration endpoint
            test_data = {
                'username': f'test_{secrets.token_hex(8)}',
                'email': f'test_{secrets.token_hex(8)}@example.com',
                'password': 'TestPassword123!'
            }
            
            # Make multiple rapid requests
            responses = []
            for i in range(12):  # Exceed typical rate limit
                try:
                    response = requests.post(
                        f"{self.base_url}/auth/register",
                        json=test_data,
                        timeout=2
                    )
                    responses.append(response.status_code)
                except requests.exceptions.RequestException:
                    break
            
            # Check if rate limiting is working
            rate_limited = any(code == 429 for code in responses)
            
            if rate_limited:
                self.add_result(
                    'rate_limiting',
                    'registration_rate_limit',
                    'PASS',
                    {'rate_limited_after_requests': len(responses)}
                )
            else:
                self.add_result(
                    'rate_limiting',
                    'registration_rate_limit',
                    'WARN',
                    {'no_rate_limiting_detected': True},
                    'medium'
                )
        
        except Exception as e:
            self.add_result(
                'rate_limiting',
                'rate_limit_test',
                'ERROR',
                {'error': str(e)},
                'low'
            )
    
    def check_docker_security(self):
        """Check Docker security configuration"""
        print("🐳 Checking Docker security...")
        
        dockerfile_path = Path(__file__).parent.parent / 'Dockerfile'
        
        if not dockerfile_path.exists():
            self.add_result(
                'docker',
                'dockerfile_exists',
                'FAIL',
                {'message': 'Dockerfile not found'},
                'medium'
            )
            return
        
        with open(dockerfile_path) as f:
            dockerfile_content = f.read()
        
        # Check for security best practices
        security_checks = {
            'non_root_user': 'USER app' in dockerfile_content,
            'minimal_base_image': 'python:3.11-slim' in dockerfile_content,
            'health_check': 'HEALTHCHECK' in dockerfile_content,
            'no_root_commands': 'USER root' not in dockerfile_content.split('USER app')[-1] if 'USER app' in dockerfile_content else False
        }
        
        for check, passed in security_checks.items():
            self.add_result(
                'docker',
                check,
                'PASS' if passed else 'WARN',
                {'check': check, 'passed': passed},
                'low' if passed else 'medium'
            )
    
    def generate_report(self, output_file=None):
        """Generate audit report"""
        print("\n📊 Generating security audit report...")
        
        # Count results by status
        stats = {
            'PASS': len([r for r in self.results if r['status'] == 'PASS']),
            'WARN': len([r for r in self.results if r['status'] == 'WARN']),
            'FAIL': len([r for r in self.results if r['status'] == 'FAIL']),
            'ERROR': len([r for r in self.results if r['status'] == 'ERROR'])
        }
        
        # Count by severity
        severity_stats = {
            'high': len([r for r in self.results if r['severity'] == 'high']),
            'medium': len([r for r in self.results if r['severity'] == 'medium']),
            'low': len([r for r in self.results if r['severity'] == 'low']),
            'info': len([r for r in self.results if r['severity'] == 'info'])
        }
        
        report = {
            'audit_metadata': {
                'timestamp': self.timestamp,
                'service': 'auth-microservice',
                'version': '1.0.0',
                'auditor': 'Security Audit Script'
            },
            'summary': {
                'total_checks': len(self.results),
                'status_breakdown': stats,
                'severity_breakdown': severity_stats,
                'overall_score': self._calculate_score()
            },
            'results': self.results,
            'recommendations': self._generate_recommendations()
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"📝 Report saved to: {output_file}")
        
        return report
    
    def _calculate_score(self):
        """Calculate overall security score"""
        if not self.results:
            return 0
        
        weights = {'PASS': 1, 'WARN': 0.5, 'FAIL': 0, 'ERROR': 0}
        total_score = sum(weights.get(r['status'], 0) for r in self.results)
        max_score = len(self.results)
        
        return round((total_score / max_score) * 100, 1)
    
    def _generate_recommendations(self):
        """Generate security recommendations"""
        recommendations = []
        
        failures = [r for r in self.results if r['status'] in ['FAIL', 'WARN']]
        
        for failure in failures:
            if failure['category'] == 'environment' and 'missing_variables' in failure['details']:
                recommendations.append({
                    'priority': 'high',
                    'category': 'environment',
                    'action': f"Add missing environment variables: {', '.join(failure['details']['missing_variables'])}"
                })
            
            elif failure['category'] == 'jwt' and 'key' in failure['test_name']:
                recommendations.append({
                    'priority': 'high',
                    'category': 'jwt',
                    'action': f"Fix JWT key issue: {failure['test_name']}"
                })
            
            elif failure['category'] == 'api' and 'security_headers' in failure['test_name']:
                recommendations.append({
                    'priority': 'medium',
                    'category': 'api',
                    'action': f"Add missing security headers: {', '.join(failure['details'].get('missing_headers', []))}"
                })
        
        return recommendations
    
    def print_summary(self):
        """Print audit summary to console"""
        stats = {
            'PASS': len([r for r in self.results if r['status'] == 'PASS']),
            'WARN': len([r for r in self.results if r['status'] == 'WARN']),
            'FAIL': len([r for r in self.results if r['status'] == 'FAIL']),
            'ERROR': len([r for r in self.results if r['status'] == 'ERROR'])
        }
        
        print(f"\n🔒 Security Audit Summary")
        print(f"{'='*50}")
        print(f"✅ Passed: {stats['PASS']}")
        print(f"⚠️  Warnings: {stats['WARN']}")
        print(f"❌ Failed: {stats['FAIL']}")
        print(f"🔴 Errors: {stats['ERROR']}")
        print(f"📊 Overall Score: {self._calculate_score()}%")
        
        if stats['FAIL'] > 0 or stats['ERROR'] > 0:
            print(f"\n⚠️  Critical Issues Found:")
            for result in self.results:
                if result['status'] in ['FAIL', 'ERROR'] and result['severity'] == 'high':
                    print(f"   • {result['category']}: {result['test_name']}")

def main():
    """Main function"""
    print("🛡️  Auth Microservice Security Audit")
    print("=" * 50)
    
    auditor = SecurityAuditor()
    
    # Run all security checks
    auditor.check_environment_security()
    auditor.check_jwt_keys()
    auditor.check_api_security()
    auditor.check_rate_limiting()
    auditor.check_docker_security()
    
    # Generate and save report
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    report_file = f"security_audit_{timestamp}.json"
    
    auditor.generate_report(report_file)
    auditor.print_summary()
    
    print(f"\n📋 Detailed report saved to: {report_file}")

if __name__ == "__main__":
    main()
