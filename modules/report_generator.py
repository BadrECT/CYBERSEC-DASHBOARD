import json
import csv
from datetime import datetime
import os

class ReportGenerator:
    def __init__(self, output_dir="."):
        self.output_dir = output_dir
    
    def generate_port_scan_report(self, target, open_ports, scan_time):
        """Génère un rapport de scan de ports"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"port_scan_{target}_{timestamp}"
        
        # Données du rapport
        report_data = {
            "scan_info": {
                "target": target,
                "scan_time": scan_time,
                "timestamp": datetime.now().isoformat(),
                "total_ports_scanned": open_ports[-1] - open_ports[0] + 1 if open_ports else 0,
                "open_ports_count": len(open_ports)
            },
            "open_ports": open_ports,
            "security_assessment": self.assess_port_security(open_ports)
        }
        
        # Générer les rapports dans le dossier courant
        self._generate_json_report(report_data, filename)
        self._generate_csv_report(report_data, filename)
        self._generate_text_report(report_data, filename)
        
        return filename
    
    def generate_password_report(self, password_data):
        """Génère un rapport d'analyse de mot de passe"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"password_analysis_{timestamp}"
        
        report_data = {
            "analysis_info": {
                "timestamp": datetime.now().isoformat(),
                "password_length": len(password_data['password']),
                "score": password_data['score'],
                "rating": password_data['rating'],
                "compromised": password_data['compromised']
            },
            "detailed_feedback": password_data['feedback'],
            "recommendations": self._generate_password_recommendations(password_data)
        }
        
        self._generate_json_report(report_data, filename)
        self._generate_text_report(report_data, filename)
        
        return filename
    
    def assess_port_security(self, open_ports):
        """Évalue la sécurité basée sur les ports ouverts"""
        common_risky_ports = {
            21: "FTP - Risque: Élevé (authentification en clair)",
            22: "SSH - Risque: Faible (si bien configuré)",
            23: "Telnet - Risque: Très élevé (pas de chiffrement)",
            25: "SMTP - Risque: Moyen",
            53: "DNS - Risque: Faible",
            80: "HTTP - Risque: Moyen",
            110: "POP3 - Risque: Élevé",
            143: "IMAP - Risque: Élevé",
            443: "HTTPS - Risque: Faible",
            993: "IMAPS - Risque: Faible",
            995: "POP3S - Risque: Faible",
            1433: "MSSQL - Risque: Élevé",
            3306: "MySQL - Risque: Élevé",
            3389: "RDP - Risque: Élevé",
            5432: "PostgreSQL - Risque: Élevé",
            5900: "VNC - Risque: Élevé",
            8080: "HTTP Proxy - Risque: Moyen"
        }
        
        risks = []
        for port in open_ports:
            if port in common_risky_ports:
                risks.append({
                    "port": port,
                    "service": common_risky_ports[port].split(" - ")[0],
                    "risk_level": common_risky_ports[port].split("Risque: ")[1].split(")")[0] + ")",
                    "description": common_risky_ports[port]
                })
        
        # Déterminer le niveau de risque global
        risk_count = len(risks)
        if risk_count >= 3:
            overall_risk = "Élevé"
        elif risk_count >= 1:
            overall_risk = "Moyen"
        else:
            overall_risk = "Faible"
        
        return {
            "risky_ports": risks,
            "overall_risk": overall_risk,
            "risk_ports_count": risk_count
        }
    
    def _generate_json_report(self, data, filename):
        """Génère un rapport JSON"""
        filepath = f"{filename}.json"
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"📄 Rapport JSON généré: {filepath}")
    
    def _generate_csv_report(self, data, filename):
        """Génère un rapport CSV pour les scans de ports"""
        if "open_ports" in data:
            filepath = f"{filename}.csv"
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Port", "Service", "Statut"])
                
                # Ajouter les services connus
                service_mapping = {
                    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
                    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
                    993: "IMAPS", 995: "POP3S", 3389: "RDP", 5900: "VNC"
                }
                
                for port in data["open_ports"]:
                    service = service_mapping.get(port, "Inconnu")
                    writer.writerow([port, service, "OUVERT"])
            print(f"📊 Rapport CSV généré: {filepath}")
    
    def _generate_text_report(self, data, filename):
        """Génère un rapport texte lisible"""
        filepath = f"{filename}.txt"
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("="*60 + "\n")
            f.write("RAPPORT DE CYBERSÉCURITÉ\n")
            f.write("="*60 + "\n\n")
            
            if "scan_info" in data:  # Rapport de scan de ports
                f.write("📡 SCAN DE PORTS\n")
                f.write("-" * 40 + "\n")
                f.write(f"Cible: {data['scan_info']['target']}\n")
                f.write(f"Date: {data['scan_info']['timestamp']}\n")
                f.write(f"Temps de scan: {data['scan_info']['scan_time']}\n")
                f.write(f"Ports scannés: {data['scan_info']['total_ports_scanned']}\n")
                f.write(f"Ports ouverts: {len(data['open_ports'])}\n")
                f.write(f"Liste des ports: {', '.join(map(str, data['open_ports']))}\n\n")
                
                f.write("⚠️  ÉVALUATION DE SÉCURITÉ\n")
                f.write("-" * 40 + "\n")
                f.write(f"Niveau de risque global: {data['security_assessment']['overall_risk']}\n")
                
                if data['security_assessment']['risky_ports']:
                    f.write(f"\nPorts à risque identifiés: {data['security_assessment']['risk_ports_count']}\n")
                    for risk in data['security_assessment']['risky_ports']:
                        f.write(f"  • Port {risk['port']} ({risk['service']}) - {risk['risk_level']}\n")
                        f.write(f"    Description: {risk['description']}\n")
                else:
                    f.write("\n✅ Aucun port à risque identifié\n")
            
            elif "analysis_info" in data:  # Rapport de mot de passe
                f.write("🔐 ANALYSE DE MOT DE PASSE\n")
                f.write("-" * 40 + "\n")
                f.write(f"Score de sécurité: {data['analysis_info']['score']}/100\n")
                f.write(f"Évaluation: {data['analysis_info']['rating']}\n")
                f.write(f"Longueur: {data['analysis_info']['password_length']} caractères\n")
                f.write(f"Compromis dans des fuites: {'✅ OUI' if data['analysis_info']['compromised'] else '❌ NON'}\n\n")
                
                f.write("📊 DÉTAILS DE L'ANALYSE\n")
                f.write("-" * 40 + "\n")
                for check, passed in data['detailed_feedback'].items():
                    status = "✅" if passed else "❌"
                    check_name = check.replace('_', ' ').title()
                    f.write(f"  {status} {check_name}\n")
                
                f.write("\n💡 RECOMMANDATIONS\n")
                f.write("-" * 40 + "\n")
                for i, rec in enumerate(data['recommendations'], 1):
                    f.write(f"  {i}. {rec}\n")
            
            f.write(f"\n" + "="*60 + "\n")
            f.write(f"Rapport généré le: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*60 + "\n")
        
        print(f"📝 Rapport texte généré: {filepath}")
    
    def _generate_password_recommendations(self, password_data):
        """Génère des recommandations basées sur l'analyse du mot de passe"""
        recommendations = []
        feedback = password_data['feedback']
        
        if not feedback['length']:
            recommendations.append("Utilisez au moins 12 caractères pour plus de sécurité")
        if not feedback['uppercase']:
            recommendations.append("Ajoutez des lettres majuscules (A-Z)")
        if not feedback['lowercase']:
            recommendations.append("Ajoutez des lettres minuscules (a-z)")
        if not feedback['numbers']:
            recommendations.append("Incluez des chiffres (0-9)")
        if not feedback['special_chars']:
            recommendations.append("Ajoutez des caractères spéciaux (!@#$%^&* etc.)")
        if feedback['common_password']:
            recommendations.append("Évitez les mots de passe courants et facilement devinables")
        
        if password_data['score'] < 60:
            recommendations.append("Envisagez d'utiliser un gestionnaire de mots de passe pour générer des mots de passe forts")
        
        if password_data['compromised']:
            recommendations.insert(0, "🚨 URGENT: Ce mot de passe a été compromis dans des fuites de données - CHANGEZ-LE IMMÉDIATEMENT!")
        
        # Ajouter des recommandations générales
        if len(recommendations) == 0:
            recommendations.append("✅ Excellent! Votre mot de passe respecte les bonnes pratiques de sécurité")
        else:
            recommendations.append("Utilisez un mot de passe unique pour chaque compte")
        
        return recommendations