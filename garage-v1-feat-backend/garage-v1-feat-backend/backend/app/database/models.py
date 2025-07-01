# backend/app/database/models.py

from typing import Optional
from sqlmodel import Field, SQLModel, Relationship


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    firstname: str
    lastname: str
    email: str = Field(unique=True, index=True)
    hashed_password: str
    photo_name: Optional[str] = None
    is_admin: bool = Field(default=False)


class Item(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    description: Optional[str] = None # <--- DOIT ÊTRE OPTIONAL !
    price: float
    tax: Optional[float] = None
    # AUCUNE LIGNE 'image_url' ICI !