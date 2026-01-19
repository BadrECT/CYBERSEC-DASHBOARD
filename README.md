# 🛡️ CYBERSEC DASHBOARD

![CyberSec Dashboard Badge](https://img.shields.io/badge/Security-Tool-red?style=for-the-badge&logo=kalilinux)
![Python Version](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-Web%20App-lightgrey?style=for-the-badge&logo=flask)

**CyberSec Dashboard** est un outil de cybersécurité tout-en-un doté d'une interface web moderne et réactive. Il permet aux utilisateurs d'effectuer des audits de sécurité de base, notamment le scan de ports réseau et l'analyse approfondie de la robustesse des mots de passe.

---

## 🚀 Fonctionnalités

### 📡 Scanner de Ports Réseau
- **Scan Multi-threadé** : Analyse rapide des ports ouverts sur une cible donnée (IP ou Domaine).
- **Rapports Détaillés** : Génération automatique de rapports aux formats JSON, CSV et TXT.
- **Visualisation** : Affichage clair des ports ouverts et des services associés.

### 🔐 Audit de Mots de Passe
- **Analyse de Complexité** : Évaluation sur 100 points basée sur la longueur, la casse, les chiffres et les caractères spéciaux.
- **Détection de Fuites (Breach Check)** : Vérification en temps réel si le mot de passe a été compromis dans une fuite de données (via l'API *Have I Been Pwned*), en utilisant la méthode sécurisée de k-anonymity (hachage partiel).
- **Feedback Détaillé** : Conseils précis pour améliorer la sécurité du mot de passe.

### 💻 Interface Moderne
- **Design "Cyberpunk"** : Interface sombre, épurée et immersive.
- **Tableau de Bord Réactif** : Navigation fluide entre les outils sans rechargement de page.

---

## 🛠️ Installation et Utilisation

### Prérequis
- Python 3.x installé.
- Connexion Internet (pour la vérification des fuites de mots de passe).

### Installation

1.  **Cloner le dépôt**
    ```bash
    git clone https://github.com/BadrECT/CYBERSEC-DASHBOARD.git
    cd CYBERSEC-DASHBOARD
    ```

2.  **Installer les dépendances**
    ```bash
    pip install flask requests
    ```

3.  **Lancer l'application**
    ```bash
    python app.py
    ```

4.  **Accéder au Dashboard**
    Ouvrez votre navigateur et allez sur : `http://127.0.0.1:5000`

---

## 📂 Structure du Projet

```
CYBERSEC-DASHBOARD/
│
├── app.py                  # Serveur Web Flask (Point d'entrée)
├── main.py                 # Version ligne de commande (CLI)
│
├── modules/                # Logique métier
│   ├── port_scanner.py     # Module de scan multithread
│   ├── password_checker.py # Algorithmes d'analyse et API
│   └── report_generator.py # Gestion des exports de fichiers
│
├── static/
│   └── css/
│       └── style.css       # Feuilles de style (Thème Dark)
│
├── templates/
│   └── index.html          # Interface utilisateur
│
└── README.md               # Documentation
```

---

## ⚠️ Avertissement Légal
Cet outil a été conçu à des fins **éducatives et de test uniquement**. 
- N'utilisez ce scanner que sur vos propres réseaux ou sur des cibles pour lesquelles vous avez une autorisation explicite (comme `scanme.nmap.org`).
- L'auteur décline toute responsabilité en cas d'utilisation abusive ou illégale de cet outil.

---

## 👨‍💻 Auteur
Développé avec passion pour la cybersécurité et le développement Python.

---
*N'hésitez pas à laisser une ⭐ si ce projet vous a été utile !*
