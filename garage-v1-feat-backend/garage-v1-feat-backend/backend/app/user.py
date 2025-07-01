# backend/app/database/models.py

from typing import Optional
from sqlmodel import Field, SQLModel, Relationship


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    firstname: str
    lastname: str
    email: str = Field(unique=True, index=True)
    # TRÈS IMPORTANT : Le champ pour le mot de passe haché s'appelle 'hashed_password'
    hashed_password: str
    photo_name: Optional[str] = None
    # TRÈS IMPORTANT : Le champ pour l'administrateur s'appelle 'is_admin', pas 'role'
    is_admin: bool = Field(default=False)


class Item(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    description: Optional[str] = None
    price: float
    tax: Optional[float] = None