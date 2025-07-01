# backend/app/__init__.py

import os
from typing import Annotated, Optional
from fastapi import FastAPI, HTTPException, Query, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import Field, Session, SQLModel, create_engine, select
from pydantic import BaseModel
from passlib.context import CryptContext

# Importations depuis vos modules locaux
from .database.models import User, Item
from .database import create_db_and_tables, SessionDep

# Contexte pour le hachage des mots de passe
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Importation des utilitaires de sécurité
from .security import (
    create_access_token,
    decode_access_token,
    ALGORITHM,
    ACCESS_TOKEN_EXPIRE_MINUTES
)

# Importation des dépendances
from .dependencies import get_current_user, get_current_active_user, get_current_admin_user


# Charger les variables d'environnement
from dotenv import load_dotenv
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable not set. Please ensure your .env file is correct.")

app = FastAPI()

# --- Middleware pour les en-têtes de sécurité ---
# Ce middleware est commenté pour le débogage CORS.
"""
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self' http://localhost:8000; "
            "font-src 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none';"
        )
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=()"
        return response

app.add_middleware(SecurityHeadersMiddleware)
"""

# --- Configuration CORS ---
origins = [
    "http://localhost",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- OAuth2 Scheme pour la gestion des tokens ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")

@app.on_event("startup")
def on_startup():
    create_db_and_tables()


@app.get("/")
async def root():
    return {"message": "Hello World"}

# --- AUTHENTIFICATION ---

# Fonction pour hacher le mot de passe (utilise pwd_context directement)
def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

# Fonction pour vérifier le mot de passe (utilise pwd_context directement)
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

@app.post("/api/v1/auth/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: SessionDep
):
    """
    Authentifie un utilisateur et génère un token d'accès JWT.
    """
    user = session.exec(select(User).where(User.email == form_data.username)).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(
        data={"sub": str(user.id), "username": user.email, "is_admin": user.is_admin}
    )
    return {"access_token": access_token, "token_type": "bearer"}


# --- Modèle Pydantic pour la création d'utilisateur ---
class UserCreate(BaseModel):
    firstname: str
    lastname: str
    email: str
    password: str
    photo_name: Optional[str] = None
    is_admin: bool = False

# --- USERS ---

@app.post("/api/v1/users/create", status_code=status.HTTP_201_CREATED)
async def create_user(user_data: UserCreate, session: SessionDep):
    """
    Crée un nouvel utilisateur avec hachage du mot de passe.
    """
    print(f"Tentative de création d'utilisateur avec l'email: {user_data.email}")

    existing_user = session.exec(select(User).where(User.email == user_data.email)).first()
    if existing_user:
        print(f"Erreur: L'email {user_data.email} est déjà enregistré. Conflit.")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered."
        )

    hashed_password = get_password_hash(user_data.password)

    db_user = User(
        firstname=user_data.firstname,
        lastname=user_data.lastname,
        email=user_data.email,
        hashed_password=hashed_password,
        photo_name=user_data.photo_name,
        is_admin=user_data.is_admin
    )

    try:
        session.add(db_user)
        session.commit()
        session.refresh(db_user)
        print(f"Utilisateur {db_user.email} créé avec succès. ID: {db_user.id}")

        return {
            "message": "User created successfully!",
            "id": db_user.id,
            "firstname": db_user.firstname,
            "lastname": db_user.lastname,
            "email": db_user.email,
            "is_admin": db_user.is_admin,
            "photo_name": db_user.photo_name
        }
    except Exception as e:
        session.rollback()
        print(f"Erreur lors de la création de l'utilisateur: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user due to a server error."
        )


@app.get("/api/v1/users/me")
async def read_current_user(current_user: Annotated[User, Depends(get_current_active_user)]):
    """
    Récupère les informations de l'utilisateur courant authentifié.
    """
    return current_user


@app.get("/api/v1/users/", response_model=list[User])
async def read_all_users(
    session: SessionDep,
    current_user: Annotated[User, Depends(get_current_admin_user)]
):
    """
    Récupère la liste de tous les utilisateurs (nécessite des droits d'admin).
    """
    users = session.exec(select(User)).all()
    return users


@app.delete("/api/v1/users/{user_id}")
async def delete_user(
    user_id: int,
    session: SessionDep,
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    """
    Supprime un utilisateur. Seul l'utilisateur lui-même ou un admin peut supprimer un compte.
    """
    user_to_delete = session.get(User, user_id)

    if not user_to_delete:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if current_user.id != user_id and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions to delete this user"
        )

    session.delete(user_to_delete)
    session.commit()
    return {"message": f"User {user_id} deleted successfully"}


# --- FILES ---
@app.get("/files/{file_path:path}")
async def read_file(file_path: str):
    """
    Route pour lire un fichier. À implémenter avec un retour de fichier réel si nécessaire.
    """
    return {"file_path": file_path}

# --- ITEMS ---
@app.post("/api/v1/items/create", status_code=status.HTTP_201_CREATED)
async def create_item(item: Item, session: SessionDep, current_user: Annotated[User, Depends(get_current_active_user)]):
    """
    Crée un nouvel article (nécessite une authentification).
    """
    session.add(item)
    session.commit()
    session.refresh(item)
    return item


@app.put("/api/v1/items/{item_id}")
async def update_item(item_id: int, item: Item, session: SessionDep, current_user: Annotated[User, Depends(get_current_active_user)]):
    """
    Met à jour un article (nécessite une authentification).
    """
    db_item = session.get(Item, item_id)
    if not db_item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")

    item_data = item.dict(exclude_unset=True) # Utilise .dict() pour la compatibilité avec votre code actuel
    for key, value in item_data.items():
        setattr(db_item, key, value)

    session.add(db_item)
    session.commit()
    session.refresh(db_item)
    return db_item


@app.get("/api/v1/items", response_model=list[Item])
def read_items(
    session: SessionDep,
    offset: int = 0,
    limit: Annotated[int, Query(le=100)] = 100,
) -> list[Item]:
    """
    Récupère la liste des articles (accessible publiquement ou non, selon le besoin).
    """
    items = session.exec(select(Item).offset(offset).limit(limit)).all()
    return items


@app.get("/api/v1/items/{item_id}", response_model=Item)
def read_item(item_id: int, session: SessionDep) -> Item:
    """
    Récupère un article par son ID (accessible publiquement).
    """
    item = session.get(Item, item_id)
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")
    return item


@app.delete("/api/v1/items/{item_id}")
def delete_item(item_id: int, session: SessionDep, current_user: Annotated[User, Depends(get_current_admin_user)]):
    """
    Supprime un article (nécessite des droits d'admin pour éviter le Broken Access Control).
    """
    item = session.get(Item, item_id)
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")

    session.delete(item)
    session.commit()
    return {"message": f"Item {item_id} deleted successfully"}