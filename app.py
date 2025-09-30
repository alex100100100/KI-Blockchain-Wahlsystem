import os
import json
import sqlite3
import threading
import hashlib
from time import time
from flask import Flask, request, jsonify, redirect, url_for, flash, render_template
import secrets
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from typing import Dict, Any, List

# ================= KONFIGURATION =================
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_urlsafe(32)
DB_FILE = 'blockchain.db'
lock = threading.Lock()
VALID_PARTIES = ["FDP", "CDU", "SPD", "Grüne", "Linke", "AfD", "Piraten", "Die PARTEI", "ÖDP", "Tierschutzpartei"]

# ================= DATENBANK =================
def get_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        # Blockchain-Tabelle
        db.execute('''
            CREATE TABLE IF NOT EXISTS chain (
                idx INTEGER PRIMARY KEY,
                timestamp REAL NOT NULL,
                votes TEXT NOT NULL,
                previous_hash TEXT
            )
        ''')
        # Wähler-Registrierung
        db.execute('''
            CREATE TABLE IF NOT EXISTS registered_voters (
                pubkey TEXT PRIMARY KEY,
                registered_at REAL NOT NULL,
                has_voted INTEGER DEFAULT 0
            )
        ''')
        # Node-Netzwerk
        db.execute('''
            CREATE TABLE IF NOT EXISTS nodes (
                address TEXT PRIMARY KEY
            )
        ''')
        # Initialer Block falls leer
        if db.execute('SELECT COUNT(*) FROM chain').fetchone()[0] == 0:
            db.execute(
                'INSERT INTO chain(idx, timestamp, votes, previous_hash) VALUES(?,?,?,?)',
                (1, time(), json.dumps([]), "1")
            )

init_db()

# ================= BLOCKCHAIN KERN =================
def hash_block(block):
    block_string = json.dumps(block, sort_keys=True).encode()
    return hashlib.sha256(block_string).hexdigest()

def get_last_block():
    db = get_db()
    row = db.execute('SELECT * FROM chain ORDER BY idx DESC LIMIT 1').fetchone()
    return dict(row) if row else None

def get_chain_length():
    db = get_db()
    return db.execute('SELECT COUNT(*) FROM chain').fetchone()[0]

def append_block(votes_list):
    with lock, get_db() as db:
        last = get_last_block()
        idx = last['idx'] + 1 if last else 1
        previous_hash = hash_block(last) if last else "1"
        
        block = {
            'index': idx,
            'timestamp': time(),
            'votes': votes_list,
            'previous_hash': previous_hash
        }
        
        db.execute(
            'INSERT INTO chain(idx, timestamp, votes, previous_hash) VALUES(?,?,?,?)',
            (block['index'], block['timestamp'], json.dumps(block['votes']), block['previous_hash'])
        )
        return block

# ================= CHAIN VERIFICATION =================
def verify_chain() -> Dict[str, Any]:
    """
    Überprüft die gesamte Blockchain auf Integrität
    """
    db = get_db()
    rows = db.execute('SELECT * FROM chain ORDER BY idx').fetchall()
    
    if not rows:
        return {'valid': True, 'message': 'Empty chain'}
    
    issues = []
    seen_votes = set()
    
    # Prüfe ersten Block
    first_block = dict(rows[0])
    if first_block['idx'] != 1:
        issues.append(f"First block index should be 1, got {first_block['idx']}")
    
    if first_block['previous_hash'] != "1":
        issues.append(f"First block previous_hash should be '1', got {first_block['previous_hash']}")
    
    previous_block = first_block
    
    # Iteriere durch alle Blöcke
    for i, row in enumerate(rows):
        current_block = dict(row)
        
        # Prüfe Block-Struktur
        if current_block['idx'] != i + 1:
            issues.append(f"Block index mismatch at position {i}: expected {i+1}, got {current_block['idx']}")
        
        # Prüfe previous_hash (außer beim ersten Block)
        if i > 0:
            expected_prev_hash = hash_block(previous_block)
            if current_block['previous_hash'] != expected_prev_hash:
                issues.append(f"Block {current_block['idx']}: previous_hash invalid. Expected {expected_prev_hash}, got {current_block['previous_hash']}")
        
        # Prüfe Votes im Block
        try:
            votes = json.loads(current_block['votes'])
            for vote_idx, vote in enumerate(votes):
                vote_id = f"{current_block['idx']}-{vote_idx}"
                
                # Prüfe auf Doppelstimmen
                if 'voter_pubkey' in vote:
                    vote_fingerprint = f"{vote.get('voter_pubkey')}-{vote.get('party')}-{vote.get('timestamp')}"
                    if vote_fingerprint in seen_votes:
                        issues.append(f"Duplicate vote detected: {vote_fingerprint}")
                    seen_votes.add(vote_fingerprint)
                elif 'voter_hash' in vote:
                    vote_fingerprint = f"{vote.get('voter_hash')}-{vote.get('party')}-{vote.get('timestamp')}"
                    if vote_fingerprint in seen_votes:
                        issues.append(f"Duplicate vote detected: {vote_fingerprint}")
                    seen_votes.add(vote_fingerprint)
                    
        except json.JSONDecodeError:
            issues.append(f"Block {current_block['idx']}: Invalid JSON in votes field")
        
        previous_block = current_block
    
    # Prüfe Gesamt-Konsistenz mit registrierten Wählern
    total_votes_in_chain = len(seen_votes)
    voted_in_db = db.execute('SELECT COUNT(*) FROM registered_voters WHERE has_voted=1').fetchone()[0]
    
    if total_votes_in_chain != voted_in_db:
        issues.append(f"Vote count mismatch: {total_votes_in_chain} in chain vs {voted_in_db} in database")
    
    return {
        'valid': len(issues) == 0,
        'block_count': len(rows),
        'total_votes': total_votes_in_chain,
        'issues': issues,
        'chain_hash': hash_block(previous_block) if rows else None
    }

# ================= ROUTES =================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register_voter():
    pubkey_hex = request.form.get('pubkey')
    if not pubkey_hex:
        flash('Fehlender Public Key', 'error')
        return redirect(url_for('index'))
    
    # Validiere Public Key Format
    try:
        bytes.fromhex(pubkey_hex)
        if len(pubkey_hex) != 64:  # Ed25519 Public Key Länge
            raise ValueError
    except ValueError:
        flash('Ungültiges Public Key Format', 'error')
        return redirect(url_for('index'))
    
    with lock, get_db() as db:
        # Prüfe ob bereits registriert
        existing = db.execute(
            'SELECT * FROM registered_voters WHERE pubkey=?', 
            (pubkey_hex,)
        ).fetchone()
        if existing:
            flash('Bereits registriert', 'info')
            return redirect(url_for('index'))
        
        # Registriere neuen Wähler
        db.execute(
            'INSERT INTO registered_voters(pubkey, registered_at) VALUES(?,?)',
            (pubkey_hex, time())
        )
        flash('Registrierung erfolgreich', 'success')
        return redirect(url_for('index'))

@app.route('/votes/new', methods=['POST'])
def new_vote():
    pubkey_hex = request.form.get('pubkey')
    party = request.form.get('party')
    signature_hex = request.form.get('signature')
    timestamp = request.form.get('timestamp')
    
    # Input Validation
    if not all([pubkey_hex, party, signature_hex, timestamp]):
        flash('Fehlende Daten', 'error')
        return redirect(url_for('index'))
    
    if party not in VALID_PARTIES:
        flash('Ungültige Partei', 'error')
        return redirect(url_for('index'))
    
    try:
        timestamp_float = float(timestamp)
        # Prüfe ob Timestamp nicht zu alt (5 Minuten Toleranz)
        if abs(time() - timestamp_float) > 300:
            flash('Ungültiger Timestamp', 'error')
            return redirect(url_for('index'))
    except ValueError:
        flash('Ungültiger Timestamp', 'error')
        return redirect(url_for('index'))
    
    with lock:
        db = get_db()
        
        # Prüfe Wähler-Registrierung
        voter = db.execute(
            'SELECT * FROM registered_voters WHERE pubkey=?', 
            (pubkey_hex,)
        ).fetchone()
        if not voter:
            flash('Nicht registriert', 'error')
            return redirect(url_for('index'))
        
        if voter['has_voted']:
            flash('Bereits abgestimmt', 'error')
            return redirect(url_for('index'))
        
        # Verifiziere Signatur
        try:
            pubkey_bytes = bytes.fromhex(pubkey_hex)
            verify_key = VerifyKey(pubkey_bytes)
            message = f"{party}|{timestamp}".encode()
            signature_bytes = bytes.fromhex(signature_hex)
            verify_key.verify(message, signature_bytes)
        except (BadSignatureError, ValueError) as e:
            flash('Ungültige Signatur', 'error')
            return redirect(url_for('index'))
        
        # Alles validiert → Stimme zählen
        vote_record = {
            'voter_pubkey': pubkey_hex,
            'party': party,
            'timestamp': timestamp_float
        }
        
        # Neuen Block mit dieser einen Stimme erstellen
        new_block = append_block([vote_record])
        
        # Wähler als "abgestimmt" markieren
        db.execute(
            'UPDATE registered_voters SET has_voted=1 WHERE pubkey=?',
            (pubkey_hex,)
        )
        db.commit()
        
        flash('Stimme erfolgreich abgegeben!', 'success')
        return redirect(url_for('index'))

@app.route('/votes/new_anonymous', methods=['POST'])
def new_vote_anonymous():
    """
    Alternative Version: Speichert keine voter_pubkey in der Blockchain
    Nur Hash des Public Keys für Doppelstimmenschutz
    """
    pubkey_hex = request.form.get('pubkey')
    party = request.form.get('party')
    signature_hex = request.form.get('signature')
    timestamp = request.form.get('timestamp')
    
    if not all([pubkey_hex, party, signature_hex, timestamp]):
        flash('Fehlende Daten', 'error')
        return redirect(url_for('index'))
    
    if party not in VALID_PARTIES:
        flash('Ungültige Partei', 'error')
        return redirect(url_for('index'))
    
    try:
        timestamp_float = float(timestamp)
        if abs(time() - timestamp_float) > 300:
            flash('Ungültiger Timestamp', 'error')
            return redirect(url_for('index'))
    except ValueError:
        flash('Ungültiger Timestamp', 'error')
        return redirect(url_for('index'))
    
    with lock:
        db = get_db()
        
        # Prüfe Wähler-Registrierung
        voter = db.execute(
            'SELECT * FROM registered_voters WHERE pubkey=?', 
            (pubkey_hex,)
        ).fetchone()
        if not voter:
            flash('Nicht registriert', 'error')
            return redirect(url_for('index'))
        
        if voter['has_voted']:
            flash('Bereits abgestimmt', 'error')
            return redirect(url_for('index'))
        
        # Verifiziere Signatur
        try:
            pubkey_bytes = bytes.fromhex(pubkey_hex)
            verify_key = VerifyKey(pubkey_bytes)
            message = f"{party}|{timestamp}".encode()
            signature_bytes = bytes.fromhex(signature_hex)
            verify_key.verify(message, signature_bytes)
        except (BadSignatureError, ValueError) as e:
            flash('Ungültige Signatur', 'error')
            return redirect(url_for('index'))
        
        # ✅ ANONYMER: Speichere nur Hash des Public Keys
        voter_hash = hashlib.sha256(pubkey_hex.encode()).hexdigest()[:16]  # Kürzerer Hash
        
        vote_record = {
            'voter_hash': voter_hash,  # Nicht zurückverfolgbar zum Public Key
            'party': party,
            'timestamp': timestamp_float,
            'block_index': None  # Wird beim Speichern gesetzt
        }
        
        # Stimme zu bestehenden Votes hinzufügen oder neuen Block erstellen
        last_block = get_last_block()
        current_votes = json.loads(last_block['votes']) if last_block else []
        
        # Maximal 100 Votes pro Block für Effizienz
        if len(current_votes) >= 100:
            # Neuen Block erstellen
            new_block = append_block([vote_record])
            vote_record['block_index'] = new_block['index']
        else:
            # Zu bestehendem Block hinzufügen
            current_votes.append(vote_record)
            db.execute(
                'UPDATE chain SET votes=? WHERE idx=?',
                (json.dumps(current_votes), last_block['idx'])
            )
            vote_record['block_index'] = last_block['idx']
            db.commit()
        
        # Wähler als "abgestimmt" markieren
        db.execute(
            'UPDATE registered_voters SET has_voted=1 WHERE pubkey=?',
            (pubkey_hex,)
        )
        db.commit()
        
        flash('Stimme erfolgreich anonym abgegeben!', 'success')
        return jsonify({
            'success': True,
            'voter_hash': voter_hash,
            'block_index': vote_record['block_index']
        })

@app.route('/results')
def get_results():
    db = get_db()
    rows = db.execute('SELECT votes FROM chain').fetchall()
    
    results = {party: 0 for party in VALID_PARTIES}
    total_votes = 0
    
    for row in rows:
        votes = json.loads(row['votes'])
        for vote in votes:
            if vote['party'] in results:
                results[vote['party']] += 1
                total_votes += 1
    
    return jsonify({
        'results': results,
        'total_votes': total_votes,
        'timestamp': time()
    })

@app.route('/chain')
def get_chain():
    db = get_db()
    rows = db.execute('SELECT * FROM chain ORDER BY idx').fetchall()
    
    chain = []
    for row in rows:
        chain.append({
            'index': row['idx'],
            'timestamp': row['timestamp'],
            'votes': json.loads(row['votes']),
            'previous_hash': row['previous_hash']
        })
    
    return jsonify(chain)

@app.route('/stats')
def get_stats():
    db = get_db()
    
    total_blocks = db.execute('SELECT COUNT(*) FROM chain').fetchone()[0]
    total_voters = db.execute('SELECT COUNT(*) FROM registered_voters').fetchone()[0]
    voted_count = db.execute('SELECT COUNT(*) FROM registered_voters WHERE has_voted=1').fetchone()[0]
    
    return jsonify({
        'total_blocks': total_blocks,
        'registered_voters': total_voters,
        'votes_cast': voted_count,
        'participation_rate': voted_count / total_voters if total_voters > 0 else 0
    })

@app.route('/verify', methods=['GET'])
def verify_chain_route():
    """Öffentlicher Endpoint zur Chain-Verifikation"""
    result = verify_chain()
    return jsonify(result)

# ================= TEST TOOLS =================
@app.route('/test/client')
def test_client():
    """Einfache Test-Oberfläche für Entwickler"""
    return '''
    <h2>Wahlsystem Test</h2>
    
    <h3>Registrierung</h3>
    <form action="/register" method="post">
        Public Key: <input type="text" name="pubkey" size="70"><br>
        <input type="submit" value="Registrieren">
    </form>
    
    <h3>Abstimmung</h3>
    <form action="/votes/new" method="post">
        Public Key: <input type="text" name="pubkey" size="70"><br>
        Partei: 
        <select name="party">
            <option value="SPD">SPD</option>
            <option value="CDU">CDU</option>
            <option value="Grüne">Grüne</option>
            <option value="FDP">FDP</option>
            <option value="AfD">AfD</option>
            <option value="Linke">Linke</option>
        </select><br>
        Signature: <input type="text" name="signature" size="70"><br>
        Timestamp: <input type="text" name="timestamp"><br>
        <input type="submit" value="Abstimmen">
    </form>

    <h3>Anonyme Abstimmung</h3>
    <form action="/votes/new_anonymous" method="post">
        Public Key: <input type="text" name="pubkey" size="70"><br>
        Partei: 
        <select name="party">
            <option value="SPD">SPD</option>
            <option value="CDU">CDU</option>
            <option value="Grüne">Grüne</option>
        </select><br>
        Signature: <input type="text" name="signature" size="70"><br>
        Timestamp: <input type="text" name="timestamp"><br>
        <input type="submit" value="Anonym abstimmen">
    </form>
    
    <h3>Info</h3>
    <a href="/results">Ergebnisse</a> | 
    <a href="/stats">Statistiken</a> | 
    <a href="/chain">Blockchain anzeigen</a> |
    <a href="/verify">Chain verifizieren</a> |
    <a href="/test/advanced">Erweiterte Tests</a>
    '''

@app.route('/test/advanced')
def test_advanced():
    """Erweiterte Test-Oberfläche mit Verifikation"""
    chain_status = verify_chain()
    
    return f'''
    <h2>Erweiterte Test-Oberfläche</h2>
    
    <h3>Chain Status: <span style="color: {'green' if chain_status['valid'] else 'red'}">
        {'✅ VALID' if chain_status['valid'] else '❌ INVALID'}
    </span></h3>
    
    <p>Blöcke: {chain_status['block_count']} | Votes: {chain_status['total_votes']}</p>
    
    {f"<h4>Issues:</h4><ul>{''.join(f'<li>{issue}</li>' for issue in chain_status['issues'])}</ul>" if chain_status['issues'] else ''}
    
    <h3>Tools:</h3>
    <a href="/verify">Chain verifizieren</a> | 
    <a href="/chain">Blockchain anzeigen</a> | 
    <a href="/results">Ergebnisse</a> |
    <a href="/stats">Statistiken</a>
    
    <h3>Anonyme Abstimmung (Beta):</h3>
    <form action="/votes/new_anonymous" method="post">
        Public Key: <input type="text" name="pubkey" size="70"><br>
        Partei: 
        <select name="party">
            <option value="SPD">SPD</option>
            <option value="CDU">CDU</option>
            <option value="Grüne">Grüne</option>
        </select><br>
        Signature: <input type="text" name="signature" size="70"><br>
        Timestamp: <input type="text" name="timestamp" value="{time()}"><br>
        <input type="submit" value="Anonym abstimmen">
    </form>
    '''

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)