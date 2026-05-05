"""
db/models.py
------------
SQLAlchemy ORM models for the Automated IP Risk Profiler System.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, Text, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()


class Asset(Base):
    __tablename__ = "assets"

    id                = Column(Integer,     primary_key=True, autoincrement=True)
    ip_address        = Column(String(45),  nullable=False, unique=True)
    hostname          = Column(String(255), nullable=True)
    mac_address       = Column(String(17),  nullable=True)
    open_ports        = Column(Text,        nullable=True)
    os_type           = Column(String(100), nullable=True)
    criticality_score = Column(Integer,     nullable=False, default=3)
    last_seen         = Column(DateTime,    nullable=False, default=datetime.utcnow)
    created_at        = Column(DateTime,    nullable=False, default=datetime.utcnow)

    risk_scores = relationship("RiskScore", back_populates="asset")

    def to_dict(self):
        return {
            "id": self.id, "ip_address": self.ip_address,
            "hostname": self.hostname, "mac_address": self.mac_address,
            "open_ports": self.open_ports, "os_type": self.os_type,
            "criticality_score": self.criticality_score,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }

    def __repr__(self):
        return f"<Asset {self.ip_address} | criticality={self.criticality_score}>"


class ThreatRecord(Base):
    __tablename__ = "threat_records"

    id             = Column(Integer,    primary_key=True, autoincrement=True)
    ip_address     = Column(String(45), nullable=False)
    source_api     = Column(String(50), nullable=False)
    severity_score = Column(Float,      nullable=False, default=1.0)
    details_json   = Column(Text,       nullable=True)
    queried_at     = Column(DateTime,   nullable=False, default=datetime.utcnow)

    risk_scores = relationship("RiskScore", back_populates="threat_record")

    def to_dict(self):
        return {
            "id": self.id, "ip_address": self.ip_address,
            "source_api": self.source_api, "severity_score": self.severity_score,
            "queried_at": self.queried_at.isoformat() if self.queried_at else None,
        }

    def __repr__(self):
        return f"<ThreatRecord {self.ip_address} | {self.source_api} | severity={self.severity_score}>"


class RiskScore(Base):
    __tablename__ = "risk_scores"

    id               = Column(Integer,    primary_key=True, autoincrement=True)
    asset_id         = Column(Integer,    ForeignKey("assets.id"),         nullable=False)
    threat_record_id = Column(Integer,    ForeignKey("threat_records.id"), nullable=False)
    composite_score  = Column(Float,      nullable=False)
    severity_label   = Column(String(10), nullable=False)
    acknowledged     = Column(Boolean,    nullable=False, default=False)
    created_at       = Column(DateTime,   nullable=False, default=datetime.utcnow)

    asset         = relationship("Asset",        back_populates="risk_scores")
    threat_record = relationship("ThreatRecord", back_populates="risk_scores")

    def to_dict(self):
        return {
            "id": self.id, "asset_id": self.asset_id,
            "threat_record_id": self.threat_record_id,
            "composite_score": self.composite_score,
            "severity_label": self.severity_label,
            "acknowledged": self.acknowledged,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f"<RiskScore asset={self.asset_id} | score={self.composite_score} [{self.severity_label}]>"