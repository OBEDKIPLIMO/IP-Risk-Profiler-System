"""
db/models.py
------------
SQLAlchemy ORM models for the Automated IP Risk Profiler System.

Tables:
  - Asset        : Discovered internal network devices
  - ThreatRecord : IP reputation data from external threat APIs
  - RiskScore    : Computed composite risk scores (legacy — kept for compatibility)
  - RiskAlert    : Full alert objects with acknowledgement tracking (NEW Day 17)
"""

from datetime import datetime, timezone
from sqlalchemy import (Column, Integer, String, Float, Text,
                        Boolean, DateTime, ForeignKey)
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()


# ── Helper: timezone-aware UTC now ────────────────────────────────────────
def utc_now():
    return datetime.now(timezone.utc)


class Asset(Base):
    __tablename__ = "assets"

    id                = Column(Integer,     primary_key=True, autoincrement=True)
    ip_address        = Column(String(45),  nullable=False, unique=True)
    hostname          = Column(String(255), nullable=True)
    mac_address       = Column(String(17),  nullable=True)
    open_ports        = Column(Text,        nullable=True)
    os_type           = Column(String(100), nullable=True)
    criticality_score = Column(Integer,     nullable=False, default=3)
    last_seen         = Column(DateTime,    nullable=False, default=utc_now)
    created_at        = Column(DateTime,    nullable=False, default=utc_now)

    risk_scores = relationship("RiskScore",  back_populates="asset")
    risk_alerts = relationship("RiskAlert",  back_populates="asset")

    def to_dict(self):
        return {
            "id":                self.id,
            "ip_address":        self.ip_address,
            "hostname":          self.hostname,
            "mac_address":       self.mac_address,
            "open_ports":        self.open_ports,
            "os_type":           self.os_type,
            "criticality_score": self.criticality_score,
            "last_seen":         self.last_seen.isoformat() if self.last_seen else None,
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
    queried_at     = Column(DateTime,   nullable=False, default=utc_now)

    risk_scores = relationship("RiskScore", back_populates="threat_record")
    risk_alerts = relationship("RiskAlert", back_populates="threat_record")

    def to_dict(self):
        return {
            "id":             self.id,
            "ip_address":     self.ip_address,
            "source_api":     self.source_api,
            "severity_score": self.severity_score,
            "queried_at":     self.queried_at.isoformat() if self.queried_at else None,
        }

    def __repr__(self):
        return f"<ThreatRecord {self.ip_address} | {self.source_api} | severity={self.severity_score}>"


class RiskScore(Base):
    """Legacy table — kept for compatibility. RiskAlert is now the primary alert table."""
    __tablename__ = "risk_scores"

    id               = Column(Integer,    primary_key=True, autoincrement=True)
    asset_id         = Column(Integer,    ForeignKey("assets.id"),         nullable=False)
    threat_record_id = Column(Integer,    ForeignKey("threat_records.id"), nullable=False)
    composite_score  = Column(Float,      nullable=False)
    severity_label   = Column(String(10), nullable=False)
    acknowledged     = Column(Boolean,    nullable=False, default=False)
    created_at       = Column(DateTime,   nullable=False, default=utc_now)

    asset         = relationship("Asset",        back_populates="risk_scores")
    threat_record = relationship("ThreatRecord", back_populates="risk_scores")

    def to_dict(self):
        return {
            "id":              self.id,
            "asset_id":        self.asset_id,
            "composite_score": self.composite_score,
            "severity_label":  self.severity_label,
            "acknowledged":    self.acknowledged,
            "created_at":      self.created_at.isoformat() if self.created_at else None,
        }


class RiskAlert(Base):
    """
    Full alert object produced by the Risk Correlation Engine.

    One row per (asset IP + threat query cycle).
    Upserted each time the scanner runs — always reflects latest state.

    Columns:
        alert_id        : unique integer primary key
        asset_ip        : IP address of the asset (denormalised for fast queries)
        asset_id        : FK → assets.id
        threat_record_id: FK → threat_records.id  (nullable — set when available)
        asset_criticality: the criticality score at time of alert
        threat_severity : the composite threat score at time of alert
        risk_score      : composite_risk = criticality × severity  (1–100)
        severity_label  : Low / Medium / High
        acknowledged    : False until an operator marks it reviewed
        created_at      : when alert was first generated
        updated_at      : when alert was last refreshed by a new scan
    """
    __tablename__ = "risk_alerts"

    alert_id          = Column(Integer,    primary_key=True, autoincrement=True)
    asset_ip          = Column(String(45), nullable=False, index=True)
    asset_id          = Column(Integer,    ForeignKey("assets.id"),         nullable=True)
    threat_record_id  = Column(Integer,    ForeignKey("threat_records.id"), nullable=True)
    asset_criticality = Column(Float,      nullable=False, default=1.0)
    threat_severity   = Column(Float,      nullable=False, default=1.0)
    risk_score        = Column(Float,      nullable=False, default=1.0)
    severity_label    = Column(String(10), nullable=False, default="Low")
    acknowledged      = Column(Boolean,    nullable=False, default=False)
    created_at        = Column(DateTime,   nullable=False, default=utc_now)
    updated_at        = Column(DateTime,   nullable=False, default=utc_now, onupdate=utc_now)

    asset         = relationship("Asset",        back_populates="risk_alerts")
    threat_record = relationship("ThreatRecord", back_populates="risk_alerts")

    def to_dict(self):
        return {
            "alert_id":          self.alert_id,
            "asset_ip":          self.asset_ip,
            "asset_id":          self.asset_id,
            "threat_record_id":  self.threat_record_id,
            "asset_criticality": self.asset_criticality,
            "threat_severity":   self.threat_severity,
            "risk_score":        self.risk_score,
            "severity_label":    self.severity_label,
            "acknowledged":      self.acknowledged,
            "created_at":        self.created_at.isoformat() if self.created_at else None,
            "updated_at":        self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self):
        return (f"<RiskAlert {self.asset_ip} | "
                f"score={self.risk_score} [{self.severity_label}] | "
                f"ack={self.acknowledged}>")