# backend/app/database/database.py

import os
from typing import Generator
from sqlmodel import create_engine, Session, SQLModel

# Il est crucial d'importer les modèles ici pour que SQLModel puisse les détecter
from .models import User, Item # IMPORTANT : importe bien les modèles ici

from dotenv import load_dotenv
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./database.db")

engine = create_engine(DATABASE_URL, echo=True)

def create_db_and_tables():
    print("Tentative de création/vérification des tables de la base de données...")
    SQLModel.metadata.create_all(engine)
    print("Tables de la base de données vérifiées/créées.")

def get_session() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session

from typing import Annotated
from fastapi import Depends
SessionDep = Annotated[Session, Depends(get_session)]