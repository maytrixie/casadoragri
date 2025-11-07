try:
    from flask_sqlalchemy import SQLAlchemy
except Exception:
    # Fallback stub to allow imports and static analysis when Flask-SQLAlchemy isn't available.
    # This stub enables model declarations and attribute access but does not provide a working DB session.
    # If you intend to run the app, install Flask-SQLAlchemy (`pip install Flask-SQLAlchemy`)
    # and configure the app's SQLALCHEMY_DATABASE_URI.
    class SQLAlchemy:
        def __init__(self):
            # Minimal placeholder base class for model declarations (class X(db.Model): ...)
            class ModelBase:
                pass
            self.Model = ModelBase

        def Column(self, *args, **kwargs):
            # Return a harmless placeholder for column declarations
            return None

        # Basic SQL types referenced in this module to avoid attribute errors
        Integer = int
        String = str
        Float = float
        Date = object

db = SQLAlchemy()

def update_delivery_status(delivery_id, status='delivered', notes='Marked as delivered with photo proof', user_id=None):
    """
    Update the delivery status and record a history entry.
    This defers imports so the module can be imported without resolving flask_login at import time.
    Callers can pass user_id explicitly; if omitted the function will try to use flask_login.current_user.
    """
    # Import inside the function to avoid unresolved import errors at module import time
    try:
        # Import dynamically to avoid static analyzers reporting "module not found"
        import importlib
        flask_login = importlib.import_module('flask_login')
        current_user = getattr(flask_login, 'current_user', None)
    except Exception:
        current_user = None

    # Import delivery models here to avoid circular imports at module import time;
    # adjust the import path if these models live in a different module.
    try:
        from .models import DeliveryAssignment, DeliveryStatusHistory  # Adjust the import path as needed
    except Exception:
        try:
            from models import DeliveryAssignment, DeliveryStatusHistory  # fallback
        except Exception:
            DeliveryAssignment = None
            DeliveryStatusHistory = None

    if DeliveryAssignment is None or DeliveryStatusHistory is None:
        raise RuntimeError("Delivery models are not available for updating status. Adjust the import path.")

    delivery = DeliveryAssignment.query.get(delivery_id)
    if delivery is None:
        raise ValueError(f"Delivery with id {delivery_id} not found")

    previous_status = delivery.status
    delivery.status = status

    changed_by = user_id
    if changed_by is None and current_user is not None:
        changed_by = getattr(current_user, "id", None)

    status_history = DeliveryStatusHistory(
        delivery_id=delivery.id,
        status=status,
        notes=notes,
        changed_by=changed_by
    )
    db.session.add(status_history)
    db.session.commit()

    return previous_status, delivery.status

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Float, nullable=False)
    kilo_per_unit = db.Column(db.Float, nullable=False)
    expiry_date = db.Column(db.Date, nullable=True)  # <-- Add this line