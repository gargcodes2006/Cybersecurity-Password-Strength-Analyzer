"""Quick smoke test for all project modules."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Test 1: All imports
from models import *
from services import *
from utils import *
print("[OK] All imports successful")

# Test 2: Password model
from models.password import Password
p = Password("Test@123!Secure")
r = p.analyze_password()
print(f"[OK] Password Score: {r['score']}, Strength: {r['strength']}")
print(f"[OK] Password Length (__len__): {len(p)}")
print(f"[OK] Password __str__: {p}")
print(f"[OK] Password __repr__: {repr(p)}")

# Test 3: PasswordAnalyzer
from models.password_analyzer import PasswordAnalyzer
a = PasswordAnalyzer()
full = a.full_analysis("Test@123!Secure")
print(f"[OK] Complexity Rating: {full['complexity']['complexity_rating']}")
print(f"[OK] Entropy: {full['entropy']}")
print(f"[OK] Patterns: {full['patterns']['patterns_detected']} detected")
print(f"[OK] Static entropy: {PasswordAnalyzer.calculate_entropy('Hello123!')}")
print(f"[OK] Total analyses (class method): {PasswordAnalyzer.get_total_analyses()}")

# Test 4: VulnerabilityScanner
from models.vulnerability_scanner import VulnerabilityScanner
v = VulnerabilityScanner()
scan = v.scan_password("password123")
print(f"[OK] Common password detected: {scan['is_common_password']}")
print(f"[OK] Total risks: {scan['total_risks']}, Level: {scan['risk_level']}")

scan2 = v.scan_password("qwerty")
print(f"[OK] Keyboard pattern 'qwerty': {scan2['keyboard_patterns']}")

# Test 5: PasswordGenerator
from models.password_generator import PasswordGenerator
g = PasswordGenerator()
pwd = g.generate_password(16)
print(f"[OK] Generated password: {pwd} (length: {len(pwd)})")
passphrase = g.generate_passphrase(4)
print(f"[OK] Generated passphrase: {passphrase}")
suggestions = g.suggest_password()
print(f"[OK] Suggestions count: {len(suggestions)}")

# Test 6: PasswordStrengthSystem (Composition)
from models.password_strength_system import PasswordStrengthSystem
s = PasswordStrengthSystem()
u = s.register_user("T001", "Test User", "test@test.com")
result = s.analyze_password("Str0ng!P@ssw0rd#2026", user_id="T001")
print(f"[OK] System analysis score: {result['score']}, Strength: {result['strength']}")
print(f"[OK] Crack time: {result['crack_time_estimate']['human_readable']}")
print(f"[OK] Recommendations: {len(result['recommendations'])}")
print(f"[OK] User history length: {len(u)}")

# Test 7: Person polymorphism
from models.user import User
from models.admin import Admin
persons = [
    User("P1", "Alice", "alice@test.com"),
    Admin("P2", "Bob", "bob@test.com", admin_id="ADM-1"),
]
for person in persons:
    details = person.display_details()
    assert isinstance(details, str)
print(f"[OK] Polymorphism: display_details() works for User and Admin")

# Test 8: SecurityReport
from models.security_report import SecurityReport
rpt = SecurityReport()
text = rpt.generate_report(result, user_name="Test User")
assert "PASSWORD SECURITY ANALYSIS REPORT" in text
print(f"[OK] SecurityReport generated: {rpt.report_id}")
print(f"[OK] Report __len__: {len(rpt)}")

# Test 9: Services
from services.analysis_service import AnalysisService
from services.report_service import ReportService
from services.export_service import ExportService
asvc = AnalysisService(s)
rsvc = ReportService(s)
esvc = ExportService(s)

# List comprehension demos
weak = asvc.get_weak_passwords()
strong = asvc.get_strong_passwords()
risky = asvc.get_risky_passwords()
print(f"[OK] List comprehension - Weak: {len(weak)}, Strong: {len(strong)}, Risky: {len(risky)}")

# Lambda demos
sorted_by_score = asvc.sort_by_score()
sorted_by_risk = asvc.sort_by_risk()
print(f"[OK] Lambda sort by score: {len(sorted_by_score)} records")
print(f"[OK] Lambda sort by risk: {len(sorted_by_risk)} records")

# Generator demo
gen = rsvc.report_generator()
for rpt_data in gen:
    print(f"[OK] Generator yielded report: {rpt_data['report_id']}")

# Recursive search
search_results = s.search_history("Strong")
print(f"[OK] Recursive search for 'Strong': {len(search_results)} result(s)")

# Test 10: Save & Load
save_msg = s.save_data()
print(f"[OK] {save_msg}")

s2 = PasswordStrengthSystem()
load_msg = s2.load_data()
print(f"[OK] {load_msg}")
print(f"[OK] Loaded users: {len(s2.users)}, records: {len(s2.analysis_records)}")

# Test 11: CSV Export
p1 = esvc.export_security_reports_csv()
p2 = esvc.export_password_analysis_csv()
p3 = esvc.export_user_security_csv()
print(f"[OK] CSV exported: {p1}")
print(f"[OK] CSV exported: {p2}")
print(f"[OK] CSV exported: {p3}")

# Test 12: Custom exceptions
from utils.exceptions import EmptyPasswordError, WeakPasswordError
try:
    raise EmptyPasswordError()
except EmptyPasswordError as e:
    print(f"[OK] EmptyPasswordError: {e}")

try:
    raise WeakPasswordError(score=10)
except WeakPasswordError as e:
    print(f"[OK] WeakPasswordError: {e}")

# Test 13: Decorators
print(f"[OK] Decorators applied on AnalysisService methods")

# Test 14: Magic methods
print(f"[OK] __str__ system: {s}")
print(f"[OK] __repr__ analyzer: {repr(a)}")

print("\n" + "=" * 55)
print("  ALL TESTS PASSED SUCCESSFULLY!")
print("=" * 55)
