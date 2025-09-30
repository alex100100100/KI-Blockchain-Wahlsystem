#!/usr/bin/env python3
"""
Client-Tools für das Wahlsystem
- Keypair Generation
- Signatur-Erstellung
- Test-Abstimmungen
"""

from nacl.signing import SigningKey
from nacl.encoding import HexEncoder
import requests
import time
import json

def generate_keypair():
    """Generiert ein neues Schlüsselpaar für einen Wähler"""
    private_key = SigningKey.generate()
    public_key = private_key.verify_key
    
    return {
        'private_key': private_key.encode(encoder=HexEncoder).decode('ascii'),
        'public_key': public_key.encode(encoder=HexEncoder).decode('ascii')
    }

def sign_vote(private_key_hex, party):
    """Signiert eine Stimme für eine Partei"""
    private_key = SigningKey(private_key_hex, encoder=HexEncoder)
    timestamp = str(time.time())
    message = f"{party}|{timestamp}".encode()
    signature = private_key.sign(message)
    
    return {
        'signature': signature.signature.hex(),
        'timestamp': timestamp,
        'message': message.decode()
    }

def register_voter(server_url, public_key_hex):
    """Registriert einen Wähler auf dem Server"""
    try:
        response = requests.post(f"{server_url}/register", data={
            'pubkey': public_key_hex
        }, timeout=10)
        return response
    except requests.exceptions.RequestException as e:
        print(f"❌ Fehler bei Registrierung: {e}")
        return type('MockResponse', (), {'status_code': 500, 'text': str(e)})()

def cast_vote(server_url, public_key_hex, private_key_hex, party):
    """Sendet eine signierte Stimme an den Server"""
    try:
        signature_data = sign_vote(private_key_hex, party)
        
        response = requests.post(f"{server_url}/votes/new", data={
            'pubkey': public_key_hex,
            'party': party,
            'signature': signature_data['signature'],
            'timestamp': signature_data['timestamp']
        }, timeout=10)
        return response
    except requests.exceptions.RequestException as e:
        print(f"❌ Fehler bei Stimmabgabe: {e}")
        return type('MockResponse', (), {'status_code': 500, 'text': str(e)})()

def cast_anonymous_vote(server_url, public_key_hex, private_key_hex, party):
    """Sendet eine anonyme signierte Stimme an den Server"""
    try:
        signature_data = sign_vote(private_key_hex, party)
        
        response = requests.post(f"{server_url}/votes/new_anonymous", data={
            'pubkey': public_key_hex,
            'party': party,
            'signature': signature_data['signature'],
            'timestamp': signature_data['timestamp']
        }, timeout=10)
        return response
    except requests.exceptions.RequestException as e:
        print(f"❌ Fehler bei anonymer Stimmabgabe: {e}")
        return type('MockResponse', (), {'status_code': 500, 'text': str(e)})()

def verify_chain(server_url):
    """Verifiziert die Blockchain-Integrität"""
    try:
        response = requests.get(f"{server_url}/verify", timeout=10)
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"❌ Fehler bei Chain-Verifikation: {e}")
        return {'valid': False, 'error': str(e)}

def get_results(server_url):
    """Holt aktuelle Wahlergebnisse"""
    try:
        response = requests.get(f"{server_url}/results", timeout=10)
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"❌ Fehler beim Abruf der Ergebnisse: {e}")
        return {'error': str(e)}

def get_stats(server_url):
    """Holt System-Statistiken"""
    try:
        response = requests.get(f"{server_url}/stats", timeout=10)
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"❌ Fehler beim Abruf der Statistiken: {e}")
        return {'error': str(e)}

def stress_test(server_url, num_votes=10, use_anonymous=False):
    """Führt einen Stresstest mit mehreren Stimmen durch"""
    results = []
    vote_function = cast_anonymous_vote if use_anonymous else cast_vote
    
    for i in range(num_votes):
        print(f"🧪 Teste Wähler {i+1}/{num_votes}...")
        keys = generate_keypair()
        
        # Registrieren
        reg_resp = register_voter(server_url, keys['public_key'])
        
        # Abstimmen
        vote_resp = vote_function(server_url, keys['public_key'], keys['private_key'], "SPD")
        
        results.append({
            'voter': i,
            'public_key': keys['public_key'][:16] + "...",
            'registration_status': reg_resp.status_code,
            'vote_status': vote_resp.status_code,
            'registration_response': reg_resp.text[:100],
            'vote_response': vote_resp.text[:100] if vote_resp.text else "No response"
        })
    
    return results

def demo_workflow(server_url):
    """Demonstriert einen kompletten Workflow"""
    print("🚀 STARTE DEMO-WORKFLOW")
    print("=" * 50)
    
    # 1. Schlüsselpaar generieren
    print("1. 🔑 GENERIERE SCHLÜSSELPAAR...")
    keys = generate_keypair()
    print(f"   Private Key: {keys['private_key'][:32]}...")
    print(f"   Public Key:  {keys['public_key']}")
    print()
    
    # 2. Wähler registrieren
    print("2. 📝 REGISTRIERE WÄHLER...")
    reg_resp = register_voter(server_url, keys['public_key'])
    print(f"   Status: {reg_resp.status_code}")
    print(f"   Response: {reg_resp.text}")
    print()
    
    # 3. Normale Stimme abgeben
    print("3. 🗳️ GEBE NORMALE STIMME AB...")
    vote_resp = cast_vote(server_url, keys['public_key'], keys['private_key'], "SPD")
    print(f"   Status: {vote_resp.status_code}")
    print(f"   Response: {vote_resp.text}")
    print()
    
    # 4. Zweite Stimme versuchen (sollte fehlschlagen)
    print("4. ❌ VERSUCHE ZWEITE STIMME (Doppelstimmenschutz)...")
    second_vote_resp = cast_vote(server_url, keys['public_key'], keys['private_key'], "CDU")
    print(f"   Status: {second_vote_resp.status_code}")
    print(f"   Response: {second_vote_resp.text}")
    print()
    
    # 5. Ergebnisse anzeigen
    print("5. 📊 ERGEBNISSE:")
    results = get_results(server_url)
    print(f"   {json.dumps(results, indent=2)}")
    print()
    
    # 6. Chain verifizieren
    print("6. 🔍 VERIFIZIERE BLOCKCHAIN...")
    verification = verify_chain(server_url)
    print(f"   Valid: {verification['valid']}")
    print(f"   Blöcke: {verification['block_count']}")
    print(f"   Votes: {verification['total_votes']}")
    if verification['issues']:
        print(f"   Issues: {verification['issues']}")
    print()
    
    # 7. Statistiken anzeigen
    print("7. 📈 STATISTIKEN:")
    stats = get_stats(server_url)
    print(f"   Registrierte Wähler: {stats['registered_voters']}")
    print(f"   Abgegebene Stimmen: {stats['votes_cast']}")
    print(f"   Teilnahmequote: {stats['participation_rate']:.1%}")

# Neue Test-Funktionen
if __name__ == '__main__':
    SERVER_URL = "http://localhost:5000"
    
    print("🤖 WAHLSYSTEM CLIENT TOOLS")
    print("=" * 50)
    
    # Komplette Demo
    demo_workflow(SERVER_URL)
    
    print("\n" + "=" * 50)
    print("💣 STRESS TEST MIT ANONYMEN STIMMEN...")
    
    # Stress Test mit anonymen Stimmen
    stress_results = stress_test(SERVER_URL, 3, use_anonymous=True)
    print("Stress Test Results:")
    for result in stress_results:
        print(f"  Wähler {result['voter']}: Reg={result['registration_status']}, Vote={result['vote_status']}")
    
    print("\n🔍 VERIFIZIERE NACH STRESS TEST...")
    verification_after = verify_chain(SERVER_URL)
    print(f"Chain valid: {verification_after['valid']}")
    print(f"Total votes in chain: {verification_after['total_votes']}")
    
    print("\n✅ DEMO ABGESCHLOSSEN!")