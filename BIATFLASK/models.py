from flask_sqlalchemy import SQLAlchemy
from passlib.hash import bcrypt
from typing import Optional
import datetime
import decimal

from sqlalchemy import DECIMAL, Date, String, TIMESTAMP, Text, text
from sqlalchemy.dialects.mysql import INTEGER
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

db = SQLAlchemy()

class Base(DeclarativeBase):
    pass

class Role(db.Model):
    __tablename__ = "role"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class Users(db.Model):
    __tablename__ = "users"
    IDUser = db.Column(db.Integer, primary_key=True)
    NomU = db.Column(db.String(120))
    PrenomU = db.Column(db.String(120))
    EmailU = db.Column(db.String(120), unique=True, nullable=False)
    MdpU = db.Column(db.String(255), nullable=False)
    FK_IDRole = db.Column(db.Integer, db.ForeignKey("role.id"), nullable=False)
    role = db.relationship("Role", backref="users")

    def set_password(self, raw):
        self.MdpU = bcrypt.hash(raw)

    def check_password(self, raw):
        return bcrypt.verify(raw, self.MdpU)

    def is_admin(self):
        return self.role and self.role.name == "admin"

class Incident(db.Model):
    __tablename__ = 'incident'

    IDIncident: Mapped[int] = mapped_column(INTEGER(11), primary_key=True)
    NomIncident: Mapped[str] = mapped_column(String(200), nullable=False)
    CreatedAt: Mapped[datetime.datetime] = mapped_column(TIMESTAMP, nullable=False, server_default=text('current_timestamp()'))
    SourceProbleme: Mapped[Optional[str]] = mapped_column(String(255))
    Criticite: Mapped[Optional[str]] = mapped_column(String(50))
    Priorite: Mapped[Optional[str]] = mapped_column(String(50))
    Status: Mapped[Optional[str]] = mapped_column(String(50))
    TypeIncident: Mapped[Optional[str]] = mapped_column(String(100))
    Categorie: Mapped[Optional[str]] = mapped_column(String(100))
    EtatFinal: Mapped[Optional[str]] = mapped_column(String(50))
    ModeResolution: Mapped[Optional[str]] = mapped_column(String(100))
    PlanAction: Mapped[Optional[str]] = mapped_column(Text)
    SolutionCurative: Mapped[Optional[str]] = mapped_column(Text)
    DateIncident: Mapped[Optional[datetime.date]] = mapped_column(Date)
    Ticket: Mapped[Optional[str]] = mapped_column(String(100))
    Collaborateur: Mapped[Optional[str]] = mapped_column(String(100))
    Chantier: Mapped[Optional[str]] = mapped_column(String(100))
    Chiffrage: Mapped[Optional[decimal.Decimal]] = mapped_column(DECIMAL(10, 2))


    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

