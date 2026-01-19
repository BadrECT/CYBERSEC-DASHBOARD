from flask import Flask, render_template, request, jsonify
from modules.port_scanner import PortScanner
from modules.password_checker import PasswordChecker
import time

app = Flask(__name__)

# Initialisation des outils
scanner_class = PortScanner
checker_tool = PasswordChecker()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan_ports', methods=['POST'])
def scan_ports():
    try:
        data = request.json
        target = data.get('target')
        start_port = int(data.get('start_port', 1))
        end_port = int(data.get('end_port', 1000))
        
        if not target:
            return jsonify({'success': False, 'error': 'La cible est requise'})
        
        # Lancement du scan
        start_time = time.time()
        scanner = scanner_class(target, start_port, end_port)
        open_ports = scanner.run_scan()
        duration = time.time() - start_time
        
        return jsonify({
            'success': True,
            'target': target,
            'open_ports': open_ports,
            'count': len(open_ports),
            'duration': f"{duration:.2f}"
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/check_password', methods=['POST'])
def check_password():
    try:
        data = request.json
        password = data.get('password')
        
        if not password:
            return jsonify({'success': False, 'error': 'Mot de passe requis'})
        
        score, rating, feedback = checker_tool.check_strength(password)
        breached = checker_tool.check_breach(password)
        
        return jsonify({
            'success': True,
            'score': score,
            'rating': rating,
            'feedback': feedback,
            'breached': breached
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    print("🚀 Serveur CyberSec démarré sur http://127.0.0.1:5000")
    app.run(debug=True, port=5000)
