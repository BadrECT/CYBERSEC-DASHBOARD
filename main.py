from modules.port_scanner import PortScanner
from modules.password_checker import PasswordChecker
from modules.report_generator import ReportGenerator
import time

class CyberSecurityTool:
    def __init__(self):
        self.scanner = PortScanner
        self.checker = PasswordChecker()
        self.reporter = ReportGenerator()  # Dossier courant par défaut
    
    def menu(self):
        while True:
            print("\n" + "="*50)
            print("🔒 OUTIL DE CYBERSÉCURITÉ PYTHON")
            print("="*50)
            print("1. Scanner des ports")
            print("2. Vérifier un mot de passe")
            print("3. Scanner + Rapport complet")
            print("4. Quitter")
            
            choice = input("\nChoisissez une option (1-4): ").strip()
            
            if choice == "1":
                self.port_scan_menu()
            elif choice == "2":
                self.password_check_menu()
            elif choice == "3":
                self.full_scan()
            elif choice == "4":
                print("👋 Au revoir!")
                break
            else:
                print("❌ Option invalide!")
    
    def port_scan_menu(self):
        try:
            target = input("🎯 Cible (IP ou domaine): ").strip()
            if not target:
                print("❌ Veuillez entrer une cible valide")
                return
            
            start_port = int(input("🔸 Port de départ (défaut: 1): ") or 1)
            end_port = int(input("🔹 Port de fin (défaut: 1000): ") or 1000)
            
            if start_port >= end_port:
                print("❌ Le port de fin doit être supérieur au port de départ")
                return
            
            print(f"\n🚀 Lancement du scan sur {target} (ports {start_port}-{end_port})...")
            start_time = time.time()
            
            scanner = self.scanner(target, start_port, end_port)
            open_ports = scanner.run_scan()
            scan_time = f"{time.time() - start_time:.2f} secondes"
            
            # Générer le rapport
            report_name = self.reporter.generate_port_scan_report(target, open_ports, scan_time)
            
            print(f"\n📊 RAPPORT - {target}")
            print(f"⏱️  Temps de scan: {scan_time}")
            print(f"🔓 Ports ouverts: {len(open_ports)}")
            if open_ports:
                print(f"📋 Liste: {', '.join(map(str, open_ports))}")
            else:
                print("📋 Aucun port ouvert trouvé")
            
            print(f"📁 Rapports sauvegardés: {report_name}.*")
            
        except ValueError:
            print("❌ Veuillez entrer des numéros de ports valides")
        except Exception as e:
            print(f"❌ Erreur lors du scan: {e}")
    
    def password_check_menu(self):
        try:
            password = input("🔐 Entrez le mot de passe à vérifier: ").strip()
            if not password:
                print("❌ Veuillez entrer un mot de passe")
                return
            
            print("\n🔍 Analyse en cours...")
            score, rating, feedback = self.checker.check_strength(password)
            breached = self.checker.check_breach(password)
            
            # Préparer les données pour le rapport
            pwd_data = {
                'password': '*' * len(password),  # Masquer le mot de passe
                'score': score,
                'rating': rating,
                'compromised': breached,
                'feedback': feedback
            }
            
            # Générer le rapport
            report_name = self.reporter.generate_password_report(pwd_data)
            
            print(f"\n📊 ANALYSE DU MOT DE PASSE")
            print(f"🎯 Score de sécurité: {score}/100")
            print(f"📈 Évaluation: {rating}")
            print(f"🚨 Compromis dans des fuites: {'✅ OUI' if breached else '❌ NON'}")
            print(f"📁 Rapports sauvegardés: {report_name}.*")
            
            print("\n🔍 DÉTAILS:")
            for check, passed in feedback.items():
                status = "✅" if passed else "❌"
                check_name = check.replace('_', ' ').title()
                print(f"  {status} {check_name}")
                
        except Exception as e:
            print(f"❌ Erreur lors de l'analyse: {e}")
    
    def full_scan(self):
        print("🚀 Lancement d'un scan complet...")
        try:
            # Scan de ports
            target = input("🎯 Cible pour le scan de ports: ").strip()
            if not target:
                print("❌ Cible invalide")
                return
            
            print(f"\n🔍 Scan des ports sur {target}...")
            start_time = time.time()
            scanner = self.scanner(target, 1, 100)
            open_ports = scanner.run_scan()
            port_scan_time = f"{time.time() - start_time:.2f}s"
            
            # Analyse mot de passe
            password = input("\n🔐 Mot de passe à analyser: ").strip()
            if password:
                print("🔍 Analyse du mot de passe...")
                score, rating, feedback = self.checker.check_strength(password)
                breached = self.checker.check_breach(password)
                
                # Générer rapport mot de passe
                pwd_data = {
                    'password': '*' * len(password),
                    'score': score,
                    'rating': rating,
                    'compromised': breached,
                    'feedback': feedback
                }
                pwd_report = self.reporter.generate_password_report(pwd_data)
            
            # Générer rapport ports
            port_report = self.reporter.generate_port_scan_report(target, open_ports, port_scan_time)
            
            print(f"\n🎉 SCAN COMPLÉTÉ!")
            print(f"🔓 Ports ouverts: {len(open_ports)}")
            if password:
                print(f"🔐 Sécurité mot de passe: {rating} ({score}/100)")
            print(f"📁 Rapports générés:")
            print(f"   - {port_report}.*")
            if password:
                print(f"   - {pwd_report}.*")
                
        except Exception as e:
            print(f"❌ Erreur lors du scan complet: {e}")

def main():
    print("🔒 Initialisation de l'outil de cybersécurité...")
    tool = CyberSecurityTool()
    tool.menu()

if __name__ == "__main__":
    main()