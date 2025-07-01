import os
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

# Pour charger les variables d'environnement
from dotenv import load_dotenv
load_dotenv()

# --- Configuration du Hachage des Mots de Passe ---
# Utilise bcrypt pour le hachage des mots de passe
# C'est un algorithme recommandé pour le stockage des mots de passe
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    """
    Hache un mot de passe en texte clair.
    """
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Vérifie si un mot de passe en texte clair correspond à un mot de passe haché.
    """
    return pwd_context.verify(plain_password, hashed_password)

# --- Configuration des JWT (JSON Web Tokens) ---
# Récupère la clé secrète depuis les variables d'environnement
# Assurez-vous d'avoir SECRET_KEY="votre_clé_secrète_super_forte_et_aléatoire" dans votre fichier .env
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable not set in .env file. Please generate a strong, random key.")

ALGORITHM = "HS256"  # Algorithme de signature du token (HMAC SHA-256) 
ACCESS_TOKEN_EXPIRE_MINUTES = 15 # Durée de validité du token d'accès en minutes 

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """
    Crée un token d'accès JWT.
    data: Dictionnaire des informations à inclure dans le token (payload).
          Doit inclure au moins 'sub' (subject), généralement l'ID de l'utilisateur.
    expires_delta: Durée de validité additionnelle. Si non spécifié, utilise ACCESS_TOKEN_EXPIRE_MINUTES.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire}) # Ajoute le temps d'expiration au payload
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> dict | None:
    """
    Décode et valide un token JWT.
    Retourne le payload du token si valide, None sinon.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        # Le token est invalide (mauvaise signature, expiré, etc.)
        return None