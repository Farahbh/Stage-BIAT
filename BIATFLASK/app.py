from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, Users, Role  # 👈 important : importer depuis model.py
from models import Incident
app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["http://localhost:4200"])

# Configuration MySQL (tu peux adapter le mot de passe)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/biat'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialisation de SQLAlchemy (nécessaire si db vient de model.py)
db.init_app(app)

# ========== ROUTES ==========
@app.route('/api/users', methods=['GET'])
def get_users():
    users = Users.query.all()
    result = []
    for user in users:
        result.append({
            'id': user.IDUser,
            'nom': user.NomU,
            'prenom': user.PrenomU,
            'email': user.EmailU,
            'role': user.role.name if user.role else None
        })
    return jsonify(result)

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    role = data.get('role')

    user = Users.query.filter_by(EmailU=email).first()

    if user and user.check_password(password):
        user_role = Role.query.get(user.FK_IDRole)
        if user_role and user_role.name == role:
            return jsonify({
                'msg': 'Connexion réussie',
                'user': {
                    'id': user.IDUser,
                    'nom': user.NomU,
                    'prenom': user.PrenomU,
                    'email': user.EmailU,
                    'role': user_role.name
                }
            }), 200

    return jsonify({'msg': 'Identifiants incorrects ou erreur serveur.'}), 401


@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email')
    new_password = data.get('new_password')

    user = Users.query.filter_by(EmailU=email).first()
    if user:
        hashed_password = generate_password_hash(new_password)
        user.MdpU = hashed_password
        db.session.commit()
        return jsonify({'msg': f'Mot de passe réinitialisé pour {email}'}), 200

    return jsonify({'msg': 'Utilisateur non trouvé'}), 404

@app.route('/api/users', methods=['POST'])
def create_user():
    data = request.get_json()
    print("🔽 Données reçues (AJOUT UTILISATEUR) :", data)

    # Vérification des champs requis
    nom = data.get('NomU')
    prenom = data.get('PrenomU')
    email = data.get('EmailU')
    mdp = data.get('MdpU')
    idrole = data.get('FK_IDRole')

    if not all([nom, prenom, email, mdp, idrole]):
        return jsonify({'msg': 'Champs requis manquants'}), 400

    # Vérifier si l’email existe déjà
    existing_user = Users.query.filter_by(EmailU=email).first()
    if existing_user:
        return jsonify({'msg': 'Email déjà utilisé'}), 409

    # Hachage du mot de passe
    hashed_password = generate_password_hash(mdp)

    # Création de l'utilisateur
    new_user = Users(
        NomU=nom.strip(),
        PrenomU=prenom.strip(),
        EmailU=email.strip(),
        MdpU=hashed_password,
        FK_IDRole=int(idrole)
    )

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'msg': f'✅ Utilisateur {prenom} {nom} ajouté avec succès'}), 201
    except Exception as e:
        print("❌ Erreur lors de l'ajout :", str(e))
        db.session.rollback()
        return jsonify({'msg': 'Erreur serveur lors de l’ajout'}), 500


@app.route('/api/users/<int:id>', methods=['DELETE'])
def delete_user(id):
    role = request.headers.get('X-User-Role')
    if role != 'Administrateur':
        return jsonify({'msg': 'Accès refusé'}), 403

    user = Users.query.get(id)
    if not user:
        return jsonify({'msg': 'Utilisateur non trouvé'}), 404

    db.session.delete(user)
    db.session.commit()
    return jsonify({'msg': f'Utilisateur avec ID {id} supprimé'}), 200

@app.route('/incidents', methods=['GET'])
def get_incidents():
    incidents = Incident.query.all()
    return jsonify([i.to_dict() for i in incidents])

@app.route('/incidents', methods=['POST'])
def create_incident():
    data = request.get_json()
    new_incident = Incident(
        NomIncident=data.get('nomIncident'),
        SourceProbleme=data.get('sourceProbleme'),
        Criticite=data.get('criticite'),
        Priorite=data.get('priorite'),
        Status=data.get('status'),
        TypeIncident=data.get('typeIncident'),
        Categorie=data.get('categorieIncident'),
        EtatFinal=data.get('etatFinal'),
        ModeResolution=data.get('modeResolution'),
        PlanAction=data.get('planActionIncident'),
        SolutionCurative=data.get('solutionCurative'),
        DateIncident=data.get('dateIncident'),
        Ticket=data.get('ticket'),
        Collaborateur=data.get('collaborateur'),
        Chantier=data.get('chantier'),
        Chiffrage=data.get('chiffrage')
    )
    db.session.add(new_incident)
    db.session.commit()
    return jsonify({'message': 'Incident ajouté avec succès'}), 201
# ========== LANCEMENT ==========
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # crée la table si elle n’existe pas
    app.run(debug=True)
# ========== LANCEMENT ==========

if __name__ == '__main__':
    with app.app_context():  # 👈 important pour init_app avec modèle externe
        db.create_all()
    app.run(debug=True)
