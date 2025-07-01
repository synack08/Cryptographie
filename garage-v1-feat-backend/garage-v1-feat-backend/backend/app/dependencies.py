# backend/app/dependencies.py

from typing import Annotated
from fastapi import Depends, HTTPException, status
from jose import JWTError
from sqlmodel import Session, select

from .database.models import User
# SECRET_KEY, ALGORITHM, decode_access_token sont définis dans security.py
from .security import SECRET_KEY, ALGORITHM, decode_access_token # 'oauth2_scheme' a été retiré de cet import !
from .database import get_session # S'assurer que get_session est disponible ici

# Importez OAuth2PasswordBearer directement si vous en avez besoin ici
# et définissez l'instance si elle n'est pas globale à l'application.
# Cependant, pour les dépendances, c'est généralement l'instance globale de __init__.py qui est utilisée.

# Pour utiliser oauth2_scheme défini dans __init__.py,
# vos fonctions de dépendance reçoivent le token via Depends(oauth2_scheme)
# sans avoir à l'importer directement si l'instance est globale à l'app.
# Si vous avez besoin d'importer l'instance de oauth2_scheme depuis __init__.py,
# cela crée une dépendance circulaire si __init__.py importe aussi de dependencies.py.
# La bonne pratique est que les fonctions de dépendance prennent oauth2_scheme
# comme un paramètre de Depends.


# Cette fonction est souvent un simple passe-plat pour l'utilisateur non actif
# Vous aurez besoin d'importer oauth2_scheme depuis FastAPI si vous ne voulez pas de cycle d'import.
# Une alternative est de redéfinir oauth2_scheme ici, ou de le passer en paramètre.
# Pour l'instant, supposons que oauth2_scheme est globalement accessible par FastAPI
# quand il résout les dépendances.

# Pour éviter la dépendance circulaire si oauth2_scheme est défini dans __init__.py
# et que __init__.py importe dependencies, on le passe comme argument par défaut
# ou on s'assure que FastAPI le résout.
# Si oauth2_scheme était dans security.py, l'import serait ok.
# Puisqu'il est dans __init__.py, la meilleure façon est de le laisser FastAPI injecter.
# Vous devez vous assurer que `oauth2_scheme` est bien disponible pour `Depends()`
# dans le contexte de l'application FastAPI. Il l'est car il est global dans __init__.py.
from fastapi.security import OAuth2PasswordBearer # Ajoutez cet import pour pouvoir utiliser OAuth2PasswordBearer ici

# Redéfinissez oauth2_scheme ici si vous ne pouvez pas l'importer de __init__.py
# ou si vous voulez une instance locale. Mais il est plus courant d'avoir une instance unique.
# Si vous avez une erreur sur `oauth2_scheme` après la correction ci-dessous,
# cela signifie qu'il n'est pas visible globalement pour FastAPI dans le contexte de 'dependencies'.
# La solution la plus simple est de le passer en argument si vous ne voulez pas le rendre global.
# Ou bien, pour simplifier, vous pourriez déplacer la définition de oauth2_scheme dans security.py
# et l'importer partout où c'est nécessaire. Mais pour le moment, suivons votre structure.

# Si oauth2_scheme est défini dans __init__.py et que security.py ne l'exporte pas,
# cette ligne est la bonne, mais nous allons supposer qu'il est accessible via FastAPI.
# Si ça ne marche pas, il faudrait le déplacer dans security.py.
# Pour le moment, je vais le définir ici pour s'assurer qu'il est disponible pour `Depends`.
# C'est une duplication, mais évite le cycle d'import si __init__.py importe depuis ce fichier.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    """Décode le token et retourne l'utilisateur (peut être inactif)."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_access_token(token) # Utilise la fonction de security.py
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        # Retourne juste l'ID et les infos du token pour cette fonction de base
        return {"id": user_id, "username": payload.get("username"), "is_admin": payload.get("is_admin")}
    except JWTError:
        raise credentials_exception

async def get_current_active_user(
    current_user_token_data: Annotated[dict, Depends(get_current_user)], # Utilise get_current_user
    session: Annotated[Session, Depends(get_session)] # Nécessite la session DB
):
    """Retourne l'utilisateur actif de la base de données."""
    user_id = current_user_token_data.get("id") # Récupère l'ID du dictionnaire retourné par get_current_user
    if not user_id:
        raise HTTPException(status_code=400, detail="Invalid token data: user ID missing")
    
    user = session.get(User, int(user_id))
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found in database")
    
    # Ici, vous pourriez ajouter une vérification si l'utilisateur est 'actif' si votre modèle User a un tel champ
    # if not user.is_active:
    #     raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    return user

async def get_current_admin_user(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    """Vérifie si l'utilisateur courant est un administrateur."""
    if not current_user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not an administrator")
    return current_user