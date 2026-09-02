from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func

from app.extensions import db


class OperationHistory(db.Model):
    __tablename__ = "operation_history"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(
        db.DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )

    family = db.Column(db.String(32), nullable=False, index=True)
    algorithm = db.Column(db.String(64), nullable=False, index=True)
    operation = db.Column(db.String(32), nullable=False)

    input_text = db.Column(db.Text, nullable=True)
    params = db.Column(JSONB, nullable=False, default=dict)
    output_text = db.Column(db.Text, nullable=True)

    step_trace = db.Column(JSONB, nullable=False, default=list)
    success = db.Column(db.Boolean, nullable=False, default=True)
    note = db.Column(db.Text, nullable=True)

    def __repr__(self) -> str:
        return f"<OperationHistory {self.id} {self.family}/{self.algorithm}/{self.operation}>"
