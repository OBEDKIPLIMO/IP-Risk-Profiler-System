"""
db/models.py
------------
SQLAlchemy ORM models for the Automated IP Risk Profiler System.

Tables:
  - Asset        : Discovered internal network devices
  - ThreatRecord : IP reputation data from external threat APIs
  - RiskScore    : Computed composite risk scores linking assets to threats
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Asset(db.Model):
    """
    Represents a discovered internal network device.

    Criticality Scale (1–10):
      1–3  : Low   — guest devices, IoT sensors, printers
      4–6  : Medium — workstations, developer machines
      7–9  : High  — servers, databases, domain controllers
      10   : Critical — core infrastructure (DC, financial DB)
    """
    __tablename__ = "assets"

    id               = db.Column(db.Integer,  primary_key=True)
    ip_address       = db.Column(db.String(45),  nullable=False, unique=True)  # supports IPv6
    hostname         = db.Column(db.String(255), nullable=True)
    mac_address      = db.Column(db.String(17),  nullable=True)
    open_ports       = db.Column(db.Text,         nullable=True)   # stored as comma-separated string
    os_type          = db.Column(db.String(100),  nullable=True)
    criticality_score = db.Column(db.Integer,    nullable=False, default=3)  # 1–10
    last_seen        = db.Column(db.DateTime,     nullable=False, default=datetime.utcnow)
    created_at       = db.Column(db.DateTime,     nullable=False, default=datetime.utcnow)

    # Relationship: one asset can have many risk scores
    risk_scores = db.relationship("RiskScore", backref="asset", lazy=True)

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
            "created_at":        self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f"<Asset {self.ip_address} | criticality={self.criticality_score}>"


class ThreatRecord(db.Model):
    """
    Stores the result of querying a single external IP against
    one or more threat intelligence APIs.

    severity_score: Normalised composite score (1.0–10.0)
    """
    __tablename__ = "threat_records"

    id             = db.Column(db.Integer,  primary_key=True)
    ip_address     = db.Column(db.String(45),  nullable=False)
    source_api     = db.Column(db.String(50),  nullable=False)  # e.g. "abuseipdb", "virustotal", "otx", "composite"
    severity_score = db.Column(db.Float,       nullable=False, default=1.0)  # 1.0–10.0
    raw_response   = db.Column(db.Text,        nullable=True)   # full JSON stored as string
    queried_at     = db.Column(db.DateTime,    nullable=False, default=datetime.utcnow)

    # Relationship: one threat record can link to many risk scores
    risk_scores = db.relationship("RiskScore", backref="threat_record", lazy=True)

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


class RiskScore(db.Model):
    """
    Computed composite risk score linking an internal asset
    to an external threat record.

    Formula: composite_score = asset.criticality_score × threat_record.severity_score
    Range  : 1–100
    Labels : Low (1–33), Medium (34–66), High (67–100)
    """
    __tablename__ = "risk_scores"

    id               = db.Column(db.Integer, primary_key=True)
    asset_id         = db.Column(db.Integer, db.ForeignKey("assets.id"),         nullable=False)
    threat_record_id = db.Column(db.Integer, db.ForeignKey("threat_records.id"), nullable=False)
    composite_score  = db.Column(db.Float,   nullable=False)   # 1.0–100.0
    severity_label   = db.Column(db.String(10), nullable=False) # Low / Medium / High
    acknowledged     = db.Column(db.Boolean, nullable=False, default=False)
    created_at       = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id":               self.id,
            "asset_id":         self.asset_id,
            "threat_record_id": self.threat_record_id,
            "composite_score":  self.composite_score,
            "severity_label":   self.severity_label,
            "acknowledged":     self.acknowledged,
            "created_at":       self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f"<RiskScore asset={self.asset_id} score={self.composite_score} [{self.severity_label}]>"