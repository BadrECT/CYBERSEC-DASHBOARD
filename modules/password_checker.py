import hashlib
import re
import requests
from typing import Tuple, Dict

class PasswordChecker:
    def __init__(self):
        self.common_passwords = self.load_common_passwords()
    
    def load_common_passwords(self):
        """Charge la liste des mots de passe courants"""
        common_passwords = [
            '123456', 'password', '12345678', 'qwerty', 'abc123',
            'password1', '12345', '123456789', 'letmein', 'welcome',
            'monkey', 'dragon', 'baseball', 'football', 'hello'
        ]
        return set(common_passwords)
    
    def check_strength(self, password: str) -> Tuple[int, str, Dict]:
        """Retourne un score de 0-100, une évaluation et des détails"""
        score = 0
        feedback = {
            'length': False,
            'uppercase': False,
            'lowercase': False,
            'numbers': False,
            'special_chars': False,
            'common_password': True
        }
        
        # Longueur
        if len(password) >= 8:
            score += 25
            feedback['length'] = True
        if len(password) >= 12:
            score += 10
        
        # Complexité
        if re.search(r'[A-Z]', password):
            score += 15
            feedback['uppercase'] = True
        if re.search(r'[a-z]', password):
            score += 15
            feedback['lowercase'] = True
        if re.search(r'[0-9]', password):
            score += 15
            feedback['numbers'] = True
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 20
            feedback['special_chars'] = True
        
        # Vérification mot de passe commun
        if password.lower() not in self.common_passwords:
            score += 10
            feedback['common_password'] = False
        
        # Évaluation
        if score >= 80:
            rating = "Très fort"
        elif score >= 60:
            rating = "Fort"
        elif score >= 40:
            rating = "Moyen"
        elif score >= 20:
            rating = "Faible"
        else:
            rating = "Très faible"
        
        return score, rating, feedback
    
    def check_breach(self, password: str) -> bool:
        """Vérifie si le mot de passe a été compromis (API Have I Been Pwned)"""
        try:
            # Hash le mot de passe en SHA-1
            sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
            prefix, suffix = sha1_hash[:5], sha1_hash[5:]
            
            # Appel à l'API
            response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
            if response.status_code == 200:
                hashes = (line.split(':') for line in response.text.splitlines())
                for h, count in hashes:
                    if h == suffix:
                        return True
            return False
        except Exception:
            # Si pas de connexion internet, retourne False
            return False

# Test
if __name__ == "__main__":
    checker = PasswordChecker()
    test_passwords = ["123456", "MySecurePass123!", "Azerty123$"]
    
    for pwd in test_passwords:
        score, rating, feedback = checker.check_strength(pwd)
        breached = checker.check_breach(pwd)
        print(f"🔐 '{pwd}' -> Score: {score}/100 ({rating}) - Compromis: {breached}")