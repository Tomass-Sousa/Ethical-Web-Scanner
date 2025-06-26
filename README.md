# Web Scanner - Multi-Module

Un outil Python complet et modulaire pour réaliser un audit web simple.  
Il permet de détecter plusieurs vulnérabilités courantes, analyser les configurations de sécurité, et générer un rapport détaillé.

---

## Fonctionnalités

- **Scan de ports** : détection des ports ouverts classiques (80, 443, 8080, 8443) sur la cible.
- **Analyse des headers HTTP** : vérification des headers de sécurité essentiels manquants.
- **Détection de CMS** : identification des CMS populaires (WordPress, Joomla, Drupal) à partir du contenu.
- **Test d’injection SQL basique** : détection d’erreurs SQL dans les réponses pour identifier d’éventuelles vulnérabilités SQLi.
- **Test XSS simple** : détection d’une vulnérabilité Cross-Site Scripting dans un paramètre GET.
- **Brute force sur page admin** : tentative basique de connexion brute-force sur plusieurs endpoints d’administration avec un petit jeu d’identifiants.
- **Scanner CVE simplifié** : identification de vulnérabilités connues basées sur les CMS détectés (mocké).
- **Crawler d’URLs** : exploration basique des liens internes pour collecter des URLs supplémentaires.
- **Génération de rapport** : export JSON et HTML clair avec tous les résultats.

---

## Installation

1. **Cloner le repo**

```bash
git clone https://github.com/tonpseudo/ethical-web-scanner.git
cd ethical-web-scanner
```

---

2. **Installer les dépendances Python**

Le scanner utilise requests et beautifulsoup4 :

```bash
pip install requests beautifulsoup4
```

---

## Utilisation

Lance le script Python :

```bash
python web_scanner.py
```

Tu seras invité à entrer l’URL ou l’adresse IP de la cible (exemple : http://testphp.vulnweb.com ou 192.168.1.10)

Le scanner effectuera alors toutes les étapes automatiquement :
- Scan des ports
- Vérification des headers HTTP
- Détection du CMS
- Test SQLi
- Test XSS
- Brute force admin
- Recherche de CVE connues
- Crawl des URLs internes
- Génération de rapports JSON et HTML dans le dossier courant (scan_report.json et scan_report.html)

---

## IMPORTANT - Usage légal et éthique

Ce script est conçu à des fins éducatives et pour des tests d’audit sur des cibles dont vous possédez l’autorisation explicite.
Tester des systèmes sans permission est illégal et puni par la loi.

Utilisez ce scanner uniquement :
Sur vos propres sites et serveurs
Ou sur des environnements de test explicitement autorisés

---

## Personnalisation et extension

Les ports à scanner peuvent être modifiés dans la méthode scan_ports.

La liste des CMS et signatures peut être enrichie dans detect_cms.
Le dictionnaire CVE est basique et peut être relié à une base de données réelle.
Le brute force utilise un jeu d’identifiants simple, à étendre ou remplacer selon vos besoins.
Le crawler est limité à 20 URLs pour éviter la charge.

---

## Structure du code

Classe WebScanner : centralise tous les modules d’analyse.

Méthodes pour chaque fonctionnalité (scan_ports, check_security_headers, detect_cms, etc.).
Méthode run_all() pour lancer toutes les étapes dans l’ordre.
Résultats stockés dans self.results et exportés en JSON et HTML.

---

## Limitations

Scanner très basique, ne remplace pas des outils spécialisés comme Nmap, Nikto, OWASP ZAP, etc.

Tests d’injection simples, ne couvrent pas tous les cas réels.

Brute force très rudimentaire, facilement détectable et bloqué.

Scanner CVE mocké, à compléter avec une vraie base.
